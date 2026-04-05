package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	numPadding          = 3
	numPaddingForPoll   = 8
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsConnClient struct {
	net.PacketConn

	clientID        []byte
	domain          Name
	maxPayload      int
	pollInterval    time.Duration
	pollConcurrency int

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	closed bool
	mutex  sync.Mutex
}

// computeMaxPayload returns the maximum payload bytes that can be encoded
// into a DNS QNAME of at most maxQnameLen wire-format bytes, given the
// configured domain suffix. Returns -1 if the domain already exceeds the limit.
func computeMaxPayload(maxQnameLen int, domain Name) int {
	// Domain wire size: each label costs 1 (length prefix) + len(label).
	domainWireSize := 0
	for _, label := range domain {
		domainWireSize += 1 + len(label)
	}
	// Available wire bytes for data labels = maxQnameLen - domainWireSize - 1 (null terminator)
	availableWire := maxQnameLen - domainWireSize - 1
	if availableWire <= 0 {
		return -1
	}

	// Each full 63-char label costs 64 wire bytes (1 prefix + 63 data).
	// A partial label of N chars costs N+1 wire bytes.
	fullLabels := availableWire / 64
	remainder := availableWire % 64
	base32Chars := fullLabels * 63
	if remainder > 1 {
		base32Chars += remainder - 1
	}

	// Base32 decoding: 5 bits per char, 8 bits per byte.
	maxDecodedBytes := base32Chars * 5 / 8

	// Decoded buffer layout for data packets:
	//   8B clientID + 1B padding marker + 3B padding + 1B payload length + payload
	overhead := 8 + 1 + numPadding + 1
	maxPayload := maxDecodedBytes - overhead
	if maxPayload < 0 {
		return -1
	}
	// Cap at 223: payload length stored in single byte, values >= 224 reserved.
	if maxPayload > 223 {
		maxPayload = 223
	}
	return maxPayload
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	domain, err := ParseName(c.Domain)
	if err != nil {
		return nil, err
	}

	maxQnameLen := int(c.MaxQnameLen)
	if maxQnameLen == 0 {
		maxQnameLen = 255
	}
	if maxQnameLen > 255 {
		maxQnameLen = 255
	}

	maxPayload := computeMaxPayload(maxQnameLen, domain)
	if maxPayload < 0 {
		return nil, errors.New("maxQnameLen too small for domain ", c.Domain)
	}

	pollInterval := initPollDelay
	if c.PollIntervalMs > 0 {
		pollInterval = time.Duration(c.PollIntervalMs) * time.Millisecond
	}

	pollConcurrency := 1
	if c.PollConcurrency > 0 {
		pollConcurrency = int(c.PollConcurrency)
	}
	if pollConcurrency > pollLimit {
		pollConcurrency = pollLimit
	}

	conn := &xdnsConnClient{
		PacketConn: raw,

		clientID:        make([]byte, 8),
		domain:          domain,
		maxPayload:      maxPayload,
		pollInterval:    pollInterval,
		pollConcurrency: pollConcurrency,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, 256),
		writeQueue: make(chan *packet, 256),
	}

	common.Must2(rand.Read(conn.clientID))

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	var buf [finalmask.UDPSize]byte

	for {
		if c.closed {
			break
		}

		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil || n == 0 {
			if go_errors.Is(err, net.ErrClosed) || go_errors.Is(err, io.EOF) {
				break
			}
			continue
		}

		resp, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		r := bytes.NewReader(payload)
		anyPacket := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			anyPacket = true

			buf := make([]byte, len(p))
			copy(buf, p)
			select {
			case c.readQueue <- &packet{
				p:    buf,
				addr: addr,
			}:
			default:
				errors.LogDebug(context.Background(), addr, " mask read err queue full")
			}
		}

		if anyPacket {
			for i := 0; i < c.pollConcurrency; i++ {
				select {
				case c.pollChan <- struct{}{}:
				default:
				}
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")

	close(c.pollChan)
	close(c.readQueue)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.closed = true
	close(c.writeQueue)
}

func (c *xdnsConnClient) sendLoop() {
	var addr net.Addr

	pollDelay := c.pollInterval
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p *packet
		pollTimerExpired := false

		select {
		case p = <-c.writeQueue:
		default:
			select {
			case p = <-c.writeQueue:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if p != nil {
			addr = p.addr

			select {
			case <-c.pollChan:
			default:
			}
		} else if addr != nil {
			encoded, _ := encode(nil, c.clientID, c.domain, c.maxPayload)
			p = &packet{
				p:    encoded,
				addr: addr,
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = c.pollInterval
		}
		pollTimer.Reset(pollDelay)

		if c.closed {
			return
		}

		if p != nil {
			_, err := c.PacketConn.WriteTo(p.p, p.addr)
			if go_errors.Is(err, net.ErrClosed) || go_errors.Is(err, io.ErrClosedPipe) {
				c.closed = true
				break
			}
		}
	}
}

func (c *xdnsConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, nil
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	encoded, err := encode(p, c.clientID, c.domain, c.maxPayload)
	if err != nil {
		errors.LogDebug(context.Background(), addr, " xdns wireformat err ", err, " ", len(p))
		return 0, nil
	}

	select {
	case c.writeQueue <- &packet{
		p:    encoded,
		addr: addr,
	}:
		return len(p), nil
	default:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, nil
	}
}

func (c *xdnsConnClient) Close() error {
	c.closed = true
	return c.PacketConn.Close()
}

func encode(p []byte, clientID []byte, domain Name, maxPayload int) ([]byte, error) {
	var decoded []byte
	{
		if len(p) > maxPayload {
			return nil, errors.New("too long: ", len(p), " > ", maxPayload)
		}
		if len(p) >= 224 {
			return nil, errors.New("too long")
		}
		var buf bytes.Buffer
		buf.Write(clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
			// If poll padding doesn't fit, fall back to smaller padding.
			pollDecodedSize := 8 + 1 + numPaddingForPoll
			dataDecodedSize := 8 + 1 + numPadding + 1
			if pollDecodedSize > dataDecodedSize+maxPayload {
				n = numPadding
			}
		}
		buf.WriteByte(byte(224 + n))
		_, _ = io.CopyN(&buf, rand.Reader, int64(n))
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, domain...)
	name, err := NewName(labels)
	if err != nil {
		return nil, err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &Message{
		ID:    id,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  name,
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}

	buf, err := query.WireFormat()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func dnsResponsePayload(resp *Message, domain Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != RcodeNoError {
		return nil
	}

	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		return nil
	}

	if answer.Type != RRTypeTXT {
		return nil
	}
	payload, err := DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

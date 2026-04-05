package qstunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	clientIDWidth    = 7
	dataOffsetWidth  = 3
	totalDataOffsets = 1 << (5 * dataOffsetWidth) // 32768
	sendQueryType    = 1                          // A record

	natKeepaliveInterval = 2 * time.Second
	infoSendThreshold    = 25 * time.Second
)

type packet struct {
	p    []byte
	addr net.Addr
}

type qstunnelConnClient struct {
	conn net.PacketConn // KCP's raw socket - used for sending DNS queries

	// Receive infrastructure (separate socket for IP-spoofed responses)
	recvSock *net.UDPConn

	// Config
	domain        []byte
	qnameEncoded  []byte
	fakeSendIP    string
	fakeSendPort  int
	maxDomainLen  int
	maxSubLen     int
	retries       int
	chunkLen      int
	clientIDBytes []byte
	myPublicIP    string

	// State
	dataOffset      int
	queryID         uint16
	lastWanRecvTime atomic.Int64
	dnsAddr         atomic.Pointer[net.Addr] // captured from first WriteTo

	readQueue chan *packet
	closed    bool
	mu        sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn, level int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("qstunnel requires being at the outermost level")
	}

	// Defaults
	maxDomainLen := int(c.MaxDomainLen)
	if maxDomainLen == 0 {
		maxDomainLen = 99
	}
	maxSubLen := int(c.MaxSubLen)
	if maxSubLen == 0 {
		maxSubLen = 63
	}
	if maxSubLen > 63 {
		maxSubLen = 63
	}
	fakeSendPort := int(c.FakeSendPort)
	if fakeSendPort == 0 {
		fakeSendPort = 443
	}

	// Generate random client ID to distinguish clients on the server
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<(5*clientIDWidth)))
	clientIDBytes := numberToBase32Lower(int(n.Int64()), clientIDWidth)

	qnameEncoded := encodeQName([]byte(c.Domain))

	maxEncodedDomainLen := maxDomainLen + 2
	if maxEncodedDomainLen > 255 {
		return nil, errors.New("maximum domain length exceeds 253 bytes")
	}

	chunkLen := computeChunkLen(maxEncodedDomainLen, len(qnameEncoded), maxSubLen, dataOffsetWidth, len(clientIDBytes))
	if chunkLen <= 0 {
		return nil, errors.New("maxDomainLen too small to fit any data")
	}

	// Create receive socket for IP-spoofed responses
	recvConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, errors.New("failed to create receive socket").Base(err)
	}
	recvSock := recvConn.(*net.UDPConn)

	// Resolve public IP if needed
	myPublicIP := c.MyPublicIp
	if myPublicIP == "" || myPublicIP == "auto" {
		myPublicIP = "0.0.0.0"
	}

	// Random initial state
	initOffset, _ := rand.Int(rand.Reader, big.NewInt(int64(totalDataOffsets)))
	initQID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	client := &qstunnelConnClient{
		conn:          raw,
		recvSock:      recvSock,
		domain:        []byte(c.Domain),
		qnameEncoded:  qnameEncoded,
		fakeSendIP:    c.FakeSendIp,
		fakeSendPort:  fakeSendPort,
		maxDomainLen:  maxDomainLen,
		maxSubLen:     maxSubLen,
		retries:       int(c.Retries),
		chunkLen:      chunkLen,
		clientIDBytes: clientIDBytes,
		myPublicIP:    myPublicIP,
		dataOffset:    int(initOffset.Int64()),
		queryID:       uint16(initQID.Int64()),
		readQueue:     make(chan *packet, 512),
	}

	// Send initial NAT punch packets
	fakeAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.FakeSendIp, fakeSendPort))
	if err == nil {
		for i := 0; i < 3; i++ {
			randData := make([]byte, 300)
			rand.Read(randData)
			recvSock.WriteTo(randData, fakeAddr)
		}
	}

	go client.recvLoop()
	go client.natKeepalive()

	return client, nil
}

// recvLoop reads IP-spoofed UDP packets arriving on recvSock.
func (c *qstunnelConnClient) recvLoop() {
	buf := make([]byte, 65536)
	for {
		if c.closed {
			break
		}

		n, addr, err := c.recvSock.ReadFrom(buf)
		if err != nil {
			if c.closed {
				break
			}
			continue
		}

		if n == 0 {
			continue
		}

		c.lastWanRecvTime.Store(time.Now().UnixMilli())

		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case c.readQueue <- &packet{p: data, addr: addr}:
		default:
			errors.LogDebug(context.Background(), "qstunnel client readQueue full")
		}
	}

	close(c.readQueue)
}

// natKeepalive sends periodic packets to maintain NAT binding on recvSock.
func (c *qstunnelConnClient) natKeepalive() {
	fakeAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.fakeSendIP, c.fakeSendPort))
	if err != nil {
		return
	}
	for {
		if c.closed {
			return
		}
		time.Sleep(natKeepaliveInterval)
		randData := make([]byte, 300)
		rand.Read(randData)
		c.recvSock.WriteTo(randData, fakeAddr)
	}
}

// buildInfoPacket creates an info DNS query containing client connection info.
func (c *qstunnelConnClient) buildInfoPacket() []byte {
	recvPort := c.recvSock.LocalAddr().(*net.UDPAddr).Port

	pubIP := net.ParseIP(c.myPublicIP).To4()
	if pubIP == nil {
		pubIP = net.IPv4zero.To4()
	}
	fakeIP := net.ParseIP(c.fakeSendIP).To4()
	if fakeIP == nil {
		fakeIP = net.IPv4zero.To4()
	}

	// Info payload: [4B pubIP][2B recvPort][4B fakeIP][2B fakePort]
	info := make([]byte, 12)
	copy(info[0:4], pubIP)
	binary.BigEndian.PutUint16(info[4:6], uint16(recvPort))
	copy(info[6:10], fakeIP)
	binary.BigEndian.PutUint16(info[10:12], uint16(c.fakeSendPort))

	infoEncoded := base32EncodeLower(info)

	c.mu.Lock()
	infoOffset := c.dataOffset
	c.dataOffset = (c.dataOffset + 1) % totalDataOffsets
	c.mu.Unlock()

	header := numberToBase32Lower(infoOffset, dataOffsetWidth)
	payload := append([]byte{}, c.clientIDBytes...)
	payload = append(payload, header...)
	payload = append(payload, '7', '8') // fragment_part=31 (base32 '7') + magic '8' => fragmentPart=31|32=63, notLast
	payload = append(payload, infoEncoded...)

	domain := insertDots(payload, c.maxSubLen)
	domain = append(domain, c.qnameEncoded...)

	c.mu.Lock()
	qid := c.queryID
	c.queryID++
	c.mu.Unlock()

	return buildDNSQuery(domain, qid, sendQueryType)
}

func (c *qstunnelConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, ok := <-c.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(pkt.p) {
		errors.LogDebug(context.Background(), "qstunnel client read short buffer")
		return 0, pkt.addr, nil
	}
	copy(p, pkt.p)
	return len(pkt.p), pkt.addr, nil
}

func (c *qstunnelConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > finalmask.UDPSize {
		return 0, errors.New("packet too large")
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}

	dataOffset := c.dataOffset
	c.dataOffset = (c.dataOffset + 1) % totalDataOffsets
	qidBase := c.queryID
	c.mu.Unlock()

	// Fragment data into DNS query domains
	domains := fragmentData(p, dataOffset, c.chunkLen, c.qnameEncoded, c.maxSubLen,
		dataOffsetWidth, c.maxDomainLen+2, c.clientIDBytes)
	if len(domains) == 0 {
		return 0, errors.New("fragmentation failed")
	}

	// Check if we need to prepend info packet
	var packets [][]byte
	lastRecv := c.lastWanRecvTime.Load()
	needInfo := lastRecv == 0 || time.Since(time.UnixMilli(lastRecv)) > infoSendThreshold
	if needInfo {
		packets = append(packets, c.buildInfoPacket())
	}

	// Build DNS queries for each fragment
	c.mu.Lock()
	qid := qidBase
	for _, domain := range domains {
		packets = append(packets, buildDNSQuery(domain, qid, sendQueryType))
		qid++
	}
	c.queryID = qid
	c.mu.Unlock()

	// Send DNS queries via KCP's raw socket to the DNS server (addr = 1.1.1.1:53 from KCP dial)
	for try := 0; try <= c.retries; try++ {
		for _, pkt := range packets {
			_, err := c.conn.WriteTo(pkt, addr)
			if err != nil {
				errors.LogDebug(context.Background(), "qstunnel send error: ", err)
			}
		}
	}

	return len(p), nil
}

func (c *qstunnelConnClient) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()

	c.recvSock.Close()
	return c.conn.Close()
}

func (c *qstunnelConnClient) LocalAddr() net.Addr {
	return c.recvSock.LocalAddr()
}

func (c *qstunnelConnClient) SetDeadline(t time.Time) error {
	return c.recvSock.SetDeadline(t)
}

func (c *qstunnelConnClient) SetReadDeadline(t time.Time) error {
	return c.recvSock.SetReadDeadline(t)
}

func (c *qstunnelConnClient) SetWriteDeadline(t time.Time) error {
	return c.recvSock.SetWriteDeadline(t)
}

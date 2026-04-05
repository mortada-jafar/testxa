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
	sendQueueSize    = 1024
	sendQueryType    = 1 // A record

	natKeepaliveInterval = 2 * time.Second
	infoSendThreshold    = 25 * time.Second
)

type packet struct {
	p    []byte
	addr net.Addr
}

type qstunnelConnClient struct {
	conn net.PacketConn // original raw conn, kept for lifecycle

	// Send infrastructure
	sendSocks []*net.UDPConn
	sendQueue chan *sendItem

	// Receive infrastructure
	recvSock *net.UDPConn

	// Config
	dnsIPs           []string
	domain           []byte
	qnameEncoded     []byte
	fakeSendIP       string
	fakeSendPort     int
	maxDomainLen     int
	maxSubLen        int
	retries          int
	chunkLen         int
	clientIDBytes    []byte
	myPublicIP       string
	mode             string

	// State
	dataOffset     int
	queryID        uint16
	sendSockIndex  int
	dnsIPIndex     int
	lastWanRecvTime atomic.Int64

	readQueue  chan *packet
	closed     bool
	mu         sync.Mutex
}

type sendItem struct {
	packets   [][]byte // DNS query packets
	dnsIP     string
	entryTime time.Time
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
	retries := int(c.Retries)
	sendSockCount := int(c.SendSockCount)
	if sendSockCount == 0 {
		sendSockCount = 64
	}

	// Generate client ID for n-1 mode
	var clientIDBytes []byte
	if c.Mode == "n-1" || c.Mode == "" {
		n, _ := rand.Int(rand.Reader, big.NewInt(1<<(5*clientIDWidth)))
		clientIDBytes = numberToBase32Lower(int(n.Int64()), clientIDWidth)
	}

	qnameEncoded := encodeQName([]byte(c.Domain))

	maxEncodedDomainLen := maxDomainLen + 2
	if maxEncodedDomainLen > 255 {
		return nil, errors.New("maximum domain length exceeds 253 bytes")
	}

	chunkLen := computeChunkLen(maxEncodedDomainLen, len(qnameEncoded), maxSubLen, dataOffsetWidth, len(clientIDBytes))
	if chunkLen <= 0 {
		return nil, errors.New("maxDomainLen too small to fit any data")
	}

	// Create send sockets
	sendSocks := make([]*net.UDPConn, sendSockCount)
	for i := range sendSocks {
		conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			// Clean up already created sockets
			for j := 0; j < i; j++ {
				sendSocks[j].Close()
			}
			return nil, errors.New("failed to create send socket").Base(err)
		}
		sendSocks[i] = conn.(*net.UDPConn)
	}

	// Create receive socket
	recvConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		for _, s := range sendSocks {
			s.Close()
		}
		return nil, errors.New("failed to create receive socket").Base(err)
	}
	recvSock := recvConn.(*net.UDPConn)

	// Resolve public IP if needed
	myPublicIP := c.MyPublicIp
	if myPublicIP == "" || myPublicIP == "auto" {
		myPublicIP = "0.0.0.0" // will be set later or discovered
	}

	// Random initial state
	initOffset, _ := rand.Int(rand.Reader, big.NewInt(int64(totalDataOffsets)))
	initQID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	client := &qstunnelConnClient{
		conn:          raw,
		sendSocks:     sendSocks,
		sendQueue:     make(chan *sendItem, sendQueueSize),
		recvSock:      recvSock,
		dnsIPs:        c.DnsIps,
		domain:        []byte(c.Domain),
		qnameEncoded:  qnameEncoded,
		fakeSendIP:    c.FakeSendIp,
		fakeSendPort:  fakeSendPort,
		maxDomainLen:  maxDomainLen,
		maxSubLen:     maxSubLen,
		retries:       retries,
		chunkLen:      chunkLen,
		clientIDBytes: clientIDBytes,
		myPublicIP:    myPublicIP,
		mode:          c.Mode,
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
	go client.sendLoop()
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

// sendLoop processes the send queue - sends DNS queries to DNS servers.
func (c *qstunnelConnClient) sendLoop() {
	sockIdx := 0
	for item := range c.sendQueue {
		if c.closed {
			return
		}
		if time.Since(item.entryTime) > time.Second {
			continue // drop stale
		}

		dstAddr, err := net.ResolveUDPAddr("udp4", item.dnsIP+":53")
		if err != nil {
			continue
		}

		for _, pkt := range item.packets {
			sock := c.sendSocks[sockIdx%len(c.sendSocks)]
			sockIdx++
			_, err := sock.WriteTo(pkt, dstAddr)
			if err != nil {
				errors.LogDebug(context.Background(), "qstunnel send error: ", err)
			}
		}
	}
}

// natKeepalive sends periodic packets to maintain NAT binding.
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
	// "78" prefix marks this as info packet (fragment_part=63 + magic='8' = not last, high bit)
	// Using offset counter for info separately
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

	// Send to each DNS IP with retries
	for try := 0; try <= c.retries; try++ {
		c.mu.Lock()
		dnsIP := c.dnsIPs[c.dnsIPIndex%len(c.dnsIPs)]
		c.dnsIPIndex++
		c.mu.Unlock()

		select {
		case c.sendQueue <- &sendItem{
			packets:   packets,
			dnsIP:     dnsIP,
			entryTime: time.Now(),
		}:
		default:
			// queue full, drop
		}
	}

	return len(p), nil
}

func (c *qstunnelConnClient) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()

	c.recvSock.Close()
	for _, s := range c.sendSocks {
		s.Close()
	}
	close(c.sendQueue)
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


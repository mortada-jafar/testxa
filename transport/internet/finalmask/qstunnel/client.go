package qstunnel

import (
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

// clientHub is a singleton that owns the shared recvSock.
// All WrapPacketConnClient calls share this hub.
type clientHub struct {
	recvSock      *net.UDPConn
	sendSocks     []*net.UDPConn
	sendIdx       int
	readQueue     chan *packet
	config        *Config
	qnameEncoded  []byte
	clientIDBytes []byte
	chunkLen      int
	maxDomainLen  int
	maxSubLen     int
	fakeSendPort  int
	dataOffset    int
	queryID       uint16
	lastWanRecvTime atomic.Int64
	mu            sync.Mutex
	closed        bool
}

var (
	sharedHub     *clientHub
	sharedHubOnce sync.Once
	sharedHubErr  error
)

func getOrCreateClientHub(c *Config) (*clientHub, error) {
	sharedHubOnce.Do(func() {
		sharedHub, sharedHubErr = newClientHub(c)
	})
	return sharedHub, sharedHubErr
}

func newClientHub(c *Config) (*clientHub, error) {
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
	sendSockCount := int(c.SendSockCount)
	if sendSockCount == 0 {
		sendSockCount = 512
	}

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

	// ONE receive socket shared by ALL connections
	recvConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, errors.New("failed to create receive socket").Base(err)
	}
	recvSock := recvConn.(*net.UDPConn)

	// Multiple send sockets like Python
	sendSocks := make([]*net.UDPConn, sendSockCount)
	for i := range sendSocks {
		sc, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			for j := 0; j < i; j++ {
				sendSocks[j].Close()
			}
			recvSock.Close()
			return nil, errors.New("failed to create send socket").Base(err)
		}
		sendSocks[i] = sc.(*net.UDPConn)
	}

	initOffset, _ := rand.Int(rand.Reader, big.NewInt(int64(totalDataOffsets)))
	initQID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	myPublicIP := c.MyPublicIp
	if myPublicIP == "" || myPublicIP == "auto" {
		myPublicIP = "0.0.0.0"
	}

	h := &clientHub{
		recvSock:      recvSock,
		sendSocks:     sendSocks,
		readQueue:     make(chan *packet, 65536),
		config:        c,
		qnameEncoded:  qnameEncoded,
		clientIDBytes: clientIDBytes,
		chunkLen:      chunkLen,
		maxDomainLen:  maxDomainLen,
		maxSubLen:     maxSubLen,
		fakeSendPort:  fakeSendPort,
		dataOffset:    int(initOffset.Int64()),
		queryID:       uint16(initQID.Int64()),
	}

	// NAT punch
	fakeAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.FakeSendIp, fakeSendPort))
	if err == nil {
		for i := 0; i < 3; i++ {
			rn, _ := rand.Int(rand.Reader, big.NewInt(243))
			randData := make([]byte, 257+int(rn.Int64()))
			rand.Read(randData)
			recvSock.WriteTo(randData, fakeAddr)
			time.Sleep(time.Millisecond)
		}
	}

	go h.recvLoop()
	go h.natKeepalive()

	return h, nil
}

func (h *clientHub) recvLoop() {
	buf := make([]byte, 65536)
	for {
		if h.closed {
			return
		}
		n, addr, err := h.recvSock.ReadFrom(buf)
		if err != nil {
			if h.closed {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		h.lastWanRecvTime.Store(time.Now().UnixMilli())
		data := make([]byte, n)
		copy(data, buf[:n])
		h.readQueue <- &packet{p: data, addr: addr}
	}
}

func (h *clientHub) natKeepalive() {
	fakeAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", h.config.FakeSendIp, h.fakeSendPort))
	if err != nil {
		return
	}
	for {
		if h.closed {
			return
		}
		time.Sleep(natKeepaliveInterval)
		rn, _ := rand.Int(rand.Reader, big.NewInt(243))
		randData := make([]byte, 257+int(rn.Int64()))
		rand.Read(randData)
		h.recvSock.WriteTo(randData, fakeAddr)
	}
}

func (h *clientHub) buildInfoPacket() []byte {
	recvPort := h.recvSock.LocalAddr().(*net.UDPAddr).Port

	pubIP := net.ParseIP(h.config.MyPublicIp).To4()
	if pubIP == nil {
		pubIP = net.IPv4zero.To4()
	}
	fakeIP := net.ParseIP(h.config.FakeSendIp).To4()
	if fakeIP == nil {
		fakeIP = net.IPv4zero.To4()
	}

	info := make([]byte, 12)
	copy(info[0:4], pubIP)
	binary.BigEndian.PutUint16(info[4:6], uint16(recvPort))
	copy(info[6:10], fakeIP)
	binary.BigEndian.PutUint16(info[10:12], uint16(h.fakeSendPort))

	infoEncoded := base32EncodeLower(info)

	h.mu.Lock()
	infoOffset := h.dataOffset
	h.dataOffset = (h.dataOffset + 1) % totalDataOffsets
	qid := h.queryID
	h.queryID++
	h.mu.Unlock()

	header := numberToBase32Lower(infoOffset, dataOffsetWidth)
	payload := append([]byte{}, h.clientIDBytes...)
	payload = append(payload, header...)
	payload = append(payload, '7', '8')
	payload = append(payload, infoEncoded...)

	domain := insertDots(payload, h.maxSubLen)
	domain = append(domain, h.qnameEncoded...)

	return buildDNSQuery(domain, qid, sendQueryType)
}

// qstunnelConnClient wraps a PacketConn. Each KCP dial gets one of these,
// but they all share the same clientHub for recvSock.
type qstunnelConnClient struct {
	hub  *clientHub
	conn net.PacketConn // KCP's raw socket, used for WriteTo destination addr
}

func NewConnClient(c *Config, raw net.PacketConn, level int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("qstunnel requires being at the outermost level")
	}

	hub, err := getOrCreateClientHub(c)
	if err != nil {
		return nil, err
	}

	return &qstunnelConnClient{
		hub:  hub,
		conn: raw,
	}, nil
}

func (c *qstunnelConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, ok := <-c.hub.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(pkt.p) {
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

	h := c.hub

	h.mu.Lock()
	dataOffset := h.dataOffset
	h.dataOffset = (h.dataOffset + 1) % totalDataOffsets
	qidBase := h.queryID
	h.mu.Unlock()

	domains := fragmentData(p, dataOffset, h.chunkLen, h.qnameEncoded, h.maxSubLen,
		dataOffsetWidth, h.maxDomainLen+2, h.clientIDBytes)
	if len(domains) == 0 {
		return 0, errors.New("fragmentation failed")
	}

	var packets [][]byte
	lastRecv := h.lastWanRecvTime.Load()
	needInfo := lastRecv == 0 || time.Since(time.UnixMilli(lastRecv)) > infoSendThreshold
	if needInfo {
		packets = append(packets, h.buildInfoPacket())
	}

	h.mu.Lock()
	qid := qidBase
	for _, domain := range domains {
		packets = append(packets, buildDNSQuery(domain, qid, sendQueryType))
		qid++
	}
	h.queryID = qid
	h.mu.Unlock()

	retries := int(h.config.Retries)
	for try := 0; try <= retries; try++ {
		for _, pkt := range packets {
			h.mu.Lock()
			sock := h.sendSocks[h.sendIdx%len(h.sendSocks)]
			h.sendIdx++
			h.mu.Unlock()
			sock.WriteTo(pkt, addr)
		}
	}

	return len(p), nil
}

func (c *qstunnelConnClient) Close() error {
	// Don't close the hub -- it's shared
	return c.conn.Close()
}

func (c *qstunnelConnClient) LocalAddr() net.Addr {
	return c.hub.recvSock.LocalAddr()
}

func (c *qstunnelConnClient) SetDeadline(t time.Time) error {
	return nil
}

func (c *qstunnelConnClient) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *qstunnelConnClient) SetWriteDeadline(t time.Time) error {
	return nil
}

// Suppress unused import
var _ = io.EOF

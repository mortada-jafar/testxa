package qstunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	gonet "net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	clientIDWidth    = 7
	dataOffsetWidth  = 3
	totalDataOffsets = 1 << (5 * dataOffsetWidth) // 32768
	sendQueryType    = 1                          // A record

	natKeepaliveInterval = 2 * time.Second
	infoSendThreshold    = 25 * time.Second
)

// clientHub is a singleton shared by all connections from this client.
// It owns the single recvSock for receiving IP-spoofed responses.
type clientHub struct {
	mu sync.Mutex

	recvSock  *gonet.UDPConn   // single socket for receiving spoofed responses
	sendSocks []*gonet.UDPConn // multiple send sockets (like Python's send_sock_list)
	sendIdx   int
	config    *Config

	// Encoding state
	qnameEncoded  []byte
	clientIDBytes []byte
	chunkLen      int
	maxDomainLen  int
	maxSubLen     int

	// State
	dataOffset      int
	queryID         uint16
	lastWanRecvTime atomic.Int64

	// Connection management
	conns map[uint32]*qsConn // conv -> conn
	closed bool
}

var (
	hubOnce sync.Once
	hub     *clientHub
	hubErr  error
)

func getOrCreateHub(config *Config) (*clientHub, error) {
	hubOnce.Do(func() {
		hub, hubErr = newClientHub(config)
	})
	return hub, hubErr
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

	// ONE receive socket for ALL connections
	recvConn, err := gonet.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, errors.New("failed to create receive socket").Base(err)
	}
	recvSock := recvConn.(*gonet.UDPConn)

	// Multiple send sockets (like Python's send_sock_list)
	sendSocks := make([]*gonet.UDPConn, sendSockCount)
	for i := range sendSocks {
		sc, err := gonet.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			for j := 0; j < i; j++ {
				sendSocks[j].Close()
			}
			recvSock.Close()
			return nil, errors.New("failed to create send socket").Base(err)
		}
		sendSocks[i] = sc.(*gonet.UDPConn)
	}

	initOffset, _ := rand.Int(rand.Reader, big.NewInt(int64(totalDataOffsets)))
	initQID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	h := &clientHub{
		recvSock:      recvSock,
		sendSocks:     sendSocks,
		config:        c,
		qnameEncoded:  qnameEncoded,
		clientIDBytes: clientIDBytes,
		chunkLen:      chunkLen,
		maxDomainLen:  maxDomainLen,
		maxSubLen:     maxSubLen,
		dataOffset:    int(initOffset.Int64()),
		queryID:       uint16(initQID.Int64()),
		conns:         make(map[uint32]*qsConn),
	}

	// Send initial NAT punch (same as Python: 3 packets with random size 257-499)
	fakeSendPort := int(c.FakeSendPort)
	if fakeSendPort == 0 {
		fakeSendPort = 443
	}
	fakeAddr, err := gonet.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.FakeSendIp, fakeSendPort))
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

// recvLoop reads IP-spoofed responses and dispatches to the right connection.
func (h *clientHub) recvLoop() {
	buf := make([]byte, 65536)
	for {
		if h.closed {
			return
		}

		n, _, err := h.recvSock.ReadFrom(buf)
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

		// Dispatch to all connections (KCP will filter by conv)
		h.mu.Lock()
		for _, conn := range h.conns {
			select {
			case conn.readCh <- data:
			default:
			}
		}
		h.mu.Unlock()
	}
}

func (h *clientHub) natKeepalive() {
	fakeSendPort := int(h.config.FakeSendPort)
	if fakeSendPort == 0 {
		fakeSendPort = 443
	}
	fakeAddr, err := gonet.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", h.config.FakeSendIp, fakeSendPort))
	if err != nil {
		return
	}
	for {
		if h.closed {
			return
		}
		time.Sleep(natKeepaliveInterval)
		// Random size 257-499, same as Python
		rn, _ := rand.Int(rand.Reader, big.NewInt(243))
		randData := make([]byte, 257+int(rn.Int64()))
		rand.Read(randData)
		h.recvSock.WriteTo(randData, fakeAddr)
	}
}

func (h *clientHub) buildInfoPacket() []byte {
	recvPort := h.recvSock.LocalAddr().(*gonet.UDPAddr).Port

	pubIP := gonet.ParseIP(h.config.MyPublicIp).To4()
	if pubIP == nil {
		pubIP = gonet.IPv4zero.To4()
	}
	fakeIP := gonet.ParseIP(h.config.FakeSendIp).To4()
	if fakeIP == nil {
		fakeIP = gonet.IPv4zero.To4()
	}

	info := make([]byte, 12)
	copy(info[0:4], pubIP)
	binary.BigEndian.PutUint16(info[4:6], uint16(recvPort))
	copy(info[6:10], fakeIP)
	fakeSendPort := int(h.config.FakeSendPort)
	if fakeSendPort == 0 {
		fakeSendPort = 443
	}
	binary.BigEndian.PutUint16(info[10:12], uint16(fakeSendPort))

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

func (h *clientHub) sendData(data []byte, dest gonet.Addr, sendConn gonet.PacketConn) {
	h.mu.Lock()
	dataOffset := h.dataOffset
	h.dataOffset = (h.dataOffset + 1) % totalDataOffsets
	qidBase := h.queryID
	h.mu.Unlock()

	domains := fragmentData(data, dataOffset, h.chunkLen, h.qnameEncoded, h.maxSubLen,
		dataOffsetWidth, h.maxDomainLen+2, h.clientIDBytes)
	if len(domains) == 0 {
		return
	}

	// Check if info needed
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
			sock.WriteTo(pkt, dest)
		}
	}
}

func (h *clientHub) addConn(conv uint32, c *qsConn) {
	h.mu.Lock()
	h.conns[conv] = c
	h.mu.Unlock()
}

func (h *clientHub) removeConn(conv uint32) {
	h.mu.Lock()
	delete(h.conns, conv)
	h.mu.Unlock()
}

// qsConn wraps a UDP connection to send data as DNS queries via the shared hub.
type qsConn struct {
	hub      *clientHub
	sendConn gonet.PacketConn // the underlying UDP socket for sending DNS queries
	dest     *gonet.UDPAddr   // DNS resolver address
	conv     uint32
	readCh   chan []byte
	closed   int32
}

func (c *qsConn) Read(b []byte) (int, error) {
	data, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (c *qsConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, io.ErrClosedPipe
	}
	c.hub.sendData(b, c.dest, c.sendConn)
	return len(b), nil
}

func (c *qsConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		c.hub.removeConn(c.conv)
		close(c.readCh)
	}
	return c.sendConn.Close()
}

func (c *qsConn) LocalAddr() gonet.Addr {
	return c.hub.recvSock.LocalAddr()
}

func (c *qsConn) RemoteAddr() gonet.Addr {
	return c.dest
}

func (c *qsConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *qsConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *qsConn) SetWriteDeadline(t time.Time) error {
	return nil
}

var globalConv uint32

func DialQSTunnel(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	h, err := getOrCreateHub(config)
	if err != nil {
		return nil, errors.New("failed to create client hub").Base(err)
	}

	// Create a UDP socket for sending DNS queries to the resolver
	dest.Network = net.Network_UDP
	rawConn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("failed to dial DNS resolver").Base(err)
	}

	// Extract the PacketConn and dest addr
	var sendConn gonet.PacketConn
	var destAddr *gonet.UDPAddr

	switch c := rawConn.(type) {
	case *internet.PacketConnWrapper:
		sendConn = c.PacketConn
		destAddr = c.Dest.(*gonet.UDPAddr)
	case *gonet.UDPConn:
		sendConn = c
		destAddr = c.RemoteAddr().(*gonet.UDPAddr)
	default:
		rawConn.Close()
		return nil, errors.New("unsupported connection type")
	}

	conv := atomic.AddUint32(&globalConv, 1)
	conn := &qsConn{
		hub:      h,
		sendConn: sendConn,
		dest:     destAddr,
		conv:     conv,
		readCh:   make(chan []byte, 256),
	}
	h.addConn(conv, conn)

	errors.LogInfo(ctx, "qstunnel: dialing via DNS to ", dest, " recvPort=", h.recvSock.LocalAddr())

	return conn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, DialQSTunnel))
}

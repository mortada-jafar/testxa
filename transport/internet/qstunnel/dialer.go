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
// ONE recvSock, ONE readCh -- exactly like Python's wan_main_socket.
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

	// Single shared read channel -- like Python's wan_main_socket recv
	readCh chan []byte
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
		readCh:        make(chan []byte, 1024),
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

// recvLoop reads IP-spoofed responses into the single shared readCh.
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

		errors.LogInfo(context.Background(), "qstunnel client: RECEIVED spoofed pkt len=", n)

		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case h.readCh <- data:
		default:
			errors.LogDebug(context.Background(), "qstunnel client: readCh full, dropped")
		}
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

func (h *clientHub) sendData(data []byte, dest gonet.Addr) {
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

// qsConn is a net.Conn that sends via DNS queries and reads from the shared hub.
type qsConn struct {
	hub    *clientHub
	dest   *gonet.UDPAddr // DNS resolver address
	closed int32

	// Read reassembly buffer
	readBuf []byte // accumulated raw data from spoofed packets
	pending []byte // current message being read (after length prefix parsed)
}

func (c *qsConn) Read(b []byte) (int, error) {
	for {
		// If we have pending data from a previous message, return it
		if len(c.pending) > 0 {
			n := copy(b, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}

		// Try to parse a complete framed message from readBuf
		if len(c.readBuf) >= 4 {
			msgLen := int(binary.BigEndian.Uint32(c.readBuf[0:4]))
			if len(c.readBuf) >= 4+msgLen {
				c.pending = c.readBuf[4 : 4+msgLen]
				c.readBuf = c.readBuf[4+msgLen:]
				n := copy(b, c.pending)
				c.pending = c.pending[n:]
				return n, nil
			}
		}

		// Need more data -- read from hub
		if atomic.LoadInt32(&c.closed) != 0 {
			return 0, io.EOF
		}
		data, ok := <-c.hub.readCh
		if !ok {
			return 0, io.EOF
		}
		c.readBuf = append(c.readBuf, data...)
	}
}

func (c *qsConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, io.ErrClosedPipe
	}
	c.hub.sendData(b, c.dest)
	return len(b), nil
}

func (c *qsConn) Close() error {
	atomic.StoreInt32(&c.closed, 1)
	return nil
}

func (c *qsConn) LocalAddr() gonet.Addr {
	return c.hub.recvSock.LocalAddr()
}

func (c *qsConn) RemoteAddr() gonet.Addr {
	return c.dest
}

func (c *qsConn) SetDeadline(t time.Time) error      { return nil }
func (c *qsConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *qsConn) SetWriteDeadline(t time.Time) error  { return nil }

func DialQSTunnel(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	h, err := getOrCreateHub(config)
	if err != nil {
		return nil, errors.New("failed to create client hub").Base(err)
	}

	// Resolve DNS resolver address
	dest.Network = net.Network_UDP
	destAddr := &gonet.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	}

	conn := &qsConn{
		hub:  h,
		dest: destAddr,
	}

	errors.LogInfo(ctx, "qstunnel: dialing via DNS to ", dest, " recvPort=", h.recvSock.LocalAddr())

	return conn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, DialQSTunnel))
}

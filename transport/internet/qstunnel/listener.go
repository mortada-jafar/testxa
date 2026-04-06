package qstunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	gonet "net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	recvQueryType     = 1 // A record
	serverIdleTimeout = 60 * time.Second
)

type clientSendInfo struct {
	spoofSrcIP   [4]byte
	spoofSrcPort uint16
	clientIP     [4]byte
	clientPort   uint16
	clientIPStr  string
}

type serverClient struct {
	dataHandler *dataHandler
	sendInfo    *clientSendInfo
	writeQueue  chan []byte
	lastSeen    time.Time
	mu          sync.Mutex
}

// Listener accepts connections from QS-Tunnel clients.
type Listener struct {
	mu sync.Mutex

	udpConn   *gonet.UDPConn // listens for DNS queries
	rawSockFd int            // raw socket for IP spoofing
	ipID      uint16

	recvDomains [][]string // parsed domain label lists

	clients map[string]*serverClient // clientID -> state

	// Virtual connections: each client gets a bidirectional conn
	addConn internet.ConnHandler

	// Connection tracking
	vconns map[string]*serverVConn // clientID -> virtual conn

	closed bool
}

// serverVConn represents a virtual connection to a client.
type serverVConn struct {
	listener *Listener
	clientID string
	readCh   chan []byte
	closed   atomic.Int32
}

func (c *serverVConn) Read(b []byte) (int, error) {
	data, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (c *serverVConn) Write(b []byte) (int, error) {
	c.listener.mu.Lock()
	sc, exists := c.listener.clients[c.clientID]
	c.listener.mu.Unlock()
	if !exists || sc.sendInfo == nil {
		return 0, nil // no send info yet, drop
	}

	buf := make([]byte, len(b))
	copy(buf, b)
	select {
	case sc.writeQueue <- buf:
		return len(b), nil
	default:
		return 0, nil
	}
}

func (c *serverVConn) Close() error {
	if c.closed.CompareAndSwap(0, 1) {
		close(c.readCh)
	}
	return nil
}

func (c *serverVConn) isClosed() bool {
	return c.closed.Load() != 0
}

func (c *serverVConn) LocalAddr() gonet.Addr {
	return c.listener.udpConn.LocalAddr()
}

func (c *serverVConn) RemoteAddr() gonet.Addr {
	c.listener.mu.Lock()
	sc, exists := c.listener.clients[c.clientID]
	c.listener.mu.Unlock()
	if exists && sc.sendInfo != nil {
		return &gonet.UDPAddr{
			IP:   gonet.IP(sc.sendInfo.clientIP[:]),
			Port: int(sc.sendInfo.clientPort),
		}
	}
	return &gonet.UDPAddr{}
}

func (c *serverVConn) SetDeadline(t time.Time) error      { return nil }
func (c *serverVConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *serverVConn) SetWriteDeadline(t time.Time) error  { return nil }

func ListenQSTunnel(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	// Listen for DNS queries
	listenAddr := &gonet.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}
	udpConn, err := gonet.ListenUDP("udp4", listenAddr)
	if err != nil {
		return nil, errors.New("failed to listen on ", address, ":", port).Base(err)
	}

	// Create raw socket for IP spoofing
	rawFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		udpConn.Close()
		return nil, errors.New("failed to create raw socket (need root/CAP_NET_RAW)").Base(err)
	}
	if err := syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(rawFd)
		udpConn.Close()
		return nil, errors.New("failed to set IP_HDRINCL").Base(err)
	}

	// Parse accepted domains
	var recvDomains [][]string
	for _, d := range config.RecvDomains {
		recvDomains = append(recvDomains, splitDomainStr(d))
	}

	initIPID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	l := &Listener{
		udpConn:     udpConn,
		rawSockFd:   rawFd,
		ipID:        uint16(initIPID.Int64()),
		recvDomains: recvDomains,
		clients:     make(map[string]*serverClient),
		addConn:     addConn,
		vconns:      make(map[string]*serverVConn),
	}

	go l.recvLoop()
	go l.cleanLoop()

	errors.LogInfo(ctx, "qstunnel: listening on ", address, ":", port)

	return l, nil
}

func splitDomainStr(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				labels = append(labels, toLowerStr(domain[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, toLowerStr(domain[start:]))
	}
	return labels
}

func toLowerStr(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func (l *Listener) recvLoop() {
	buf := make([]byte, 65536)
	for {
		if l.closed {
			return
		}

		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			if l.closed {
				return
			}
			continue
		}

		rawData := make([]byte, n)
		copy(rawData, buf[:n])

		// Parse DNS query
		parsed, err := handleDNSRequest(rawData)
		if err != nil {
			continue
		}
		if parsed.QType != recvQueryType {
			continue
		}

		// Check domain suffix
		matchedDomainLabels := 0
		for _, domainLabels := range l.recvDomains {
			if len(parsed.Labels) >= len(domainLabels) {
				suffix := parsed.Labels[len(parsed.Labels)-len(domainLabels):]
				if labelsEqual(suffix, domainLabels) {
					matchedDomainLabels = len(domainLabels)
					break
				}
			}
		}
		if matchedDomainLabels == 0 {
			continue
		}

		// Send DNS response
		response := createNoerrorEmptyResponse(parsed.QID, parsed.QFlags, rawData[12:parsed.NextQuestion])
		l.udpConn.WriteToUDP(response, addr)

		// Join data labels
		dataLabels := parsed.Labels[:len(parsed.Labels)-matchedDomainLabels]
		if len(dataLabels) == 0 {
			continue
		}
		var dataWithHeader []byte
		for _, lab := range dataLabels {
			dataWithHeader = append(dataWithHeader, lab...)
		}
		if len(dataWithHeader) == 0 {
			continue
		}

		// Parse chunk data
		clientID, dataOffset, fragmentPart, lastFragment, chunkData, err := parseChunkData(
			dataWithHeader, dataOffsetWidth, clientIDWidth)
		if err != nil || len(chunkData) == 0 {
			continue
		}

		clientKey := string(clientID)

		// Info packet
		if fragmentPart == 63 && !lastFragment {
			infoData, err := base32DecodeNoPad(chunkData)
			if err != nil || len(infoData) != 12 {
				continue
			}

			si := &clientSendInfo{}
			copy(si.clientIP[:], infoData[0:4])
			si.clientPort = binary.BigEndian.Uint16(infoData[4:6])
			copy(si.spoofSrcIP[:], infoData[6:10])
			si.spoofSrcPort = binary.BigEndian.Uint16(infoData[10:12])
			si.clientIPStr = gonet.IP(si.clientIP[:]).String()

			errors.LogInfo(context.Background(), "qstunnel: INFO client=", si.clientIPStr, ":", si.clientPort,
				" spoof=", gonet.IP(si.spoofSrcIP[:]).String(), ":", si.spoofSrcPort)

			l.mu.Lock()
			sc, exists := l.clients[clientKey]
			if !exists {
				dh := newDataHandler(totalDataOffsets)
				sc = &serverClient{
					dataHandler: dh,
					sendInfo:    si,
					writeQueue:  make(chan []byte, 512),
					lastSeen:    time.Now(),
				}
				l.clients[clientKey] = sc
				go l.clientSendLoop(clientKey, sc)

				// Create virtual connection for this client
				vc := &serverVConn{
					listener: l,
					clientID: clientKey,
					readCh:   make(chan []byte, 512),
				}
				l.vconns[clientKey] = vc
				l.mu.Unlock()

				// Notify Xray of new connection
				l.addConn(vc)
			} else {
				sc.mu.Lock()
				sc.sendInfo = si
				sc.lastSeen = time.Now()
				sc.mu.Unlock()
				l.mu.Unlock()
			}
			continue
		}

		// Regular data fragment
		l.mu.Lock()
		sc, exists := l.clients[clientKey]
		vc := l.vconns[clientKey]
		l.mu.Unlock()
		if !exists || vc == nil {
			continue
		}

		sc.mu.Lock()
		sc.lastSeen = time.Now()
		sc.mu.Unlock()

		assembled := sc.dataHandler.newDataEvent(dataOffset, fragmentPart, lastFragment, chunkData)
		if assembled == nil {
			continue
		}

		decoded, err := base32DecodeNoPad(assembled)
		if err != nil {
			continue
		}

		if !vc.isClosed() {
			select {
			case vc.readCh <- decoded:
			default:
			}
		}
	}
}

func labelsEqual(a [][]byte, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], []byte(b[i])) {
			return false
		}
	}
	return true
}

// clientSendLoop sends data back to a client via IP-spoofed UDP.
func (l *Listener) clientSendLoop(clientKey string, sc *serverClient) {
	for data := range sc.writeQueue {
		if l.closed {
			return
		}

		sc.mu.Lock()
		si := sc.sendInfo
		sc.mu.Unlock()

		if si == nil {
			continue
		}

		udpPayload := buildUDPPayloadV4(data, si.spoofSrcPort, si.clientPort, si.spoofSrcIP, si.clientIP)

		l.mu.Lock()
		ipID := l.ipID
		l.ipID++
		l.mu.Unlock()

		ipHeader := buildIPv4Header(len(udpPayload), si.spoofSrcIP, si.clientIP, udpProto, 128, ipID, true)

		pkt := make([]byte, len(ipHeader)+len(udpPayload))
		copy(pkt, ipHeader)
		copy(pkt[len(ipHeader):], udpPayload)

		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], si.clientIP[:])
		sa.Port = int(si.clientPort)

		if err := syscall.Sendto(l.rawSockFd, pkt, 0, &sa); err != nil {
			errors.LogDebug(context.Background(), "qstunnel: raw send error: ", err)
		}
	}
}

func (l *Listener) cleanLoop() {
	ticker := time.NewTicker(serverIdleTimeout / 2)
	defer ticker.Stop()
	for {
		if l.closed {
			return
		}
		<-ticker.C

		l.mu.Lock()
		now := time.Now()
		for key, sc := range l.clients {
			sc.mu.Lock()
			idle := now.Sub(sc.lastSeen) > serverIdleTimeout
			sc.mu.Unlock()
			if idle {
				sc.dataHandler.close()
				close(sc.writeQueue)
				delete(l.clients, key)
				if vc, ok := l.vconns[key]; ok {
					vc.Close()
					delete(l.vconns, key)
				}
			}
		}
		l.mu.Unlock()
	}
}

func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	for key, sc := range l.clients {
		sc.dataHandler.close()
		close(sc.writeQueue)
		delete(l.clients, key)
	}
	for key, vc := range l.vconns {
		vc.Close()
		delete(l.vconns, key)
	}
	l.mu.Unlock()

	l.udpConn.Close()
	syscall.Close(l.rawSockFd)
	return nil
}

func (l *Listener) Addr() gonet.Addr {
	return l.udpConn.LocalAddr()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenQSTunnel))
}

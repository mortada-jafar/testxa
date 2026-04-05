package qstunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	serverIdleTimeout = 30 * time.Second
	recvQueryType     = 1 // A record
)

type clientSendInfo struct {
	spoofSrcIP   [4]byte
	spoofSrcPort uint16
	clientIP     [4]byte
	clientPort   uint16
	clientIPStr  string
}

type clientState struct {
	dataHandler *dataHandler
	sock        *net.UDPConn
	sendInfo    *clientSendInfo
	writeQueue  chan []byte
	lastSeen    time.Time
	mu          sync.Mutex
}

type qstunnelConnServer struct {
	conn net.PacketConn // original raw conn, kept for lifecycle

	recvSock   net.PacketConn // listens for DNS queries (reuses KCP's socket)
	rawSockFd  int            // raw socket for IP spoofing
	ipID       uint16

	recvDomains [][]string // parsed domain label lists (lowercased)
	clientIDLen int

	clients   map[string]*clientState
	readQueue chan *packet

	closed bool
	mu     sync.Mutex
}

func NewConnServer(c *Config, raw net.PacketConn, level int) (net.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("qstunnel requires being at the outermost level")
	}

	// Create raw socket for IP spoofing
	rawFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, errors.New("failed to create raw socket (need root/CAP_NET_RAW)").Base(err)
	}
	if err := syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(rawFd)
		return nil, errors.New("failed to set IP_HDRINCL").Base(err)
	}

	// Parse accepted domains
	var recvDomains [][]string
	for _, d := range c.RecvDomains {
		labels := splitDomainStr(d)
		recvDomains = append(recvDomains, labels)
	}

	clientIDLen := clientIDWidth

	initIPID, _ := rand.Int(rand.Reader, big.NewInt(65536))

	server := &qstunnelConnServer{
		conn:        raw,
		recvSock:    raw, // reuse KCP's bound socket for DNS queries
		rawSockFd:   rawFd,
		ipID:        uint16(initIPID.Int64()),
		recvDomains: recvDomains,
		clientIDLen: clientIDLen,
		clients:     make(map[string]*clientState),
		readQueue:   make(chan *packet, 512),
	}

	go server.recvLoop()
	go server.cleanLoop()

	return server, nil
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

// recvLoop listens for DNS queries and processes them.
func (s *qstunnelConnServer) recvLoop() {
	buf := make([]byte, 65536)
	for {
		if s.closed {
			break
		}

		n, addr, err := s.recvSock.ReadFrom(buf)
		if err != nil {
			if s.closed {
				break
			}
			continue
		}

		rawData := make([]byte, n)
		copy(rawData, buf[:n])

		// Parse DNS query
		parsed, err := handleDNSRequest(rawData)
		if err != nil {
			errors.LogDebug(context.Background(), "qstunnel: not a DNS query, len=", n, " from ", addr)
			continue
		}
		if parsed.QType != recvQueryType {
			errors.LogDebug(context.Background(), "qstunnel: wrong qtype=", parsed.QType, " from ", addr)
			continue
		}

		// Check domain suffix
		matchedDomainLabels := 0
		for _, domainLabels := range s.recvDomains {
			if len(parsed.Labels) >= len(domainLabels) {
				suffix := parsed.Labels[len(parsed.Labels)-len(domainLabels):]
				if labelsEqual(suffix, domainLabels) {
					matchedDomainLabels = len(domainLabels)
					break
				}
			}
		}
		if matchedDomainLabels == 0 {
			errors.LogDebug(context.Background(), "qstunnel: no matching domain, labels=", parsed.Labels, " from ", addr)
			continue
		}
		errors.LogInfo(context.Background(), "qstunnel: received DNS query with ", len(parsed.Labels), " labels from ", addr)

		// Send DNS response regardless
		response := createNoerrorEmptyResponse(parsed.QID, parsed.QFlags, rawData[12:parsed.NextQuestion])
		s.recvSock.WriteTo(response, addr)

		// Join data labels (exclude domain suffix)
		dataLabels := parsed.Labels[:len(parsed.Labels)-matchedDomainLabels]
		if len(dataLabels) == 0 {
			continue
		}
		var dataWithHeader []byte
		for _, l := range dataLabels {
			dataWithHeader = append(dataWithHeader, l...)
		}
		if len(dataWithHeader) == 0 {
			continue
		}

		// Parse chunk data
		clientID, dataOffset, fragmentPart, lastFragment, chunkData, err := parseChunkData(
			dataWithHeader, dataOffsetWidth, s.clientIDLen)
		if err != nil || len(chunkData) == 0 {
			continue
		}

		clientKey := string(clientID)

		// Check if this is an info packet (fragmentPart=63, not last)
		if fragmentPart == 63 && !lastFragment {
			infoData, err := base32DecodeNoPad(chunkData)
			if err != nil || len(infoData) != 12 {
				errors.LogDebug(context.Background(), "qstunnel: invalid info packet, chunkLen=", len(chunkData), " decodedLen=", len(infoData))
				continue
			}

			si := &clientSendInfo{}
			copy(si.clientIP[:], infoData[0:4])
			si.clientPort = binary.BigEndian.Uint16(infoData[4:6])
			copy(si.spoofSrcIP[:], infoData[6:10])
			si.spoofSrcPort = binary.BigEndian.Uint16(infoData[10:12])
			si.clientIPStr = net.IP(si.clientIP[:]).String()

			errors.LogInfo(context.Background(), "qstunnel: INFO from client=", si.clientIPStr, ":", si.clientPort,
				" spoofSrc=", net.IP(si.spoofSrcIP[:]).String(), ":", si.spoofSrcPort)

			s.mu.Lock()
			cs, exists := s.clients[clientKey]
			if !exists {
				dh := newDataHandler(totalDataOffsets)
				cs = &clientState{
					dataHandler: dh,
					sendInfo:    si,
					writeQueue:  make(chan []byte, 256),
					lastSeen:    time.Now(),
				}
				s.clients[clientKey] = cs
				go s.clientSendLoop(clientKey, cs)
			} else {
				cs.mu.Lock()
				cs.sendInfo = si
				cs.lastSeen = time.Now()
				cs.mu.Unlock()
			}
			s.mu.Unlock()
			continue
		}

		// Regular data fragment
		s.mu.Lock()
		cs, exists := s.clients[clientKey]
		s.mu.Unlock()
		if !exists {
			continue
		}

		cs.mu.Lock()
		cs.lastSeen = time.Now()
		cs.mu.Unlock()

		assembled := cs.dataHandler.newDataEvent(dataOffset, fragmentPart, lastFragment, chunkData)
		if assembled == nil {
			continue
		}

		decoded, err := base32DecodeNoPad(assembled)
		if err != nil {
			continue
		}

		select {
		case s.readQueue <- &packet{
			p: decoded,
			addr: &net.UDPAddr{
				IP:   net.IP(cs.sendInfo.clientIP[:]),
				Port: int(cs.sendInfo.clientPort),
			},
		}:
		default:
			errors.LogDebug(context.Background(), "qstunnel server readQueue full")
		}
	}

	close(s.readQueue)
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

// clientSendLoop sends data to a specific client via IP-spoofed UDP packets.
func (s *qstunnelConnServer) clientSendLoop(clientKey string, cs *clientState) {
	for data := range cs.writeQueue {
		if s.closed {
			return
		}

		cs.mu.Lock()
		si := cs.sendInfo
		cs.mu.Unlock()

		if si == nil {
			continue
		}

		// Build IP-spoofed UDP packet
		udpPayload := buildUDPPayloadV4(data, si.spoofSrcPort, si.clientPort, si.spoofSrcIP, si.clientIP)

		s.mu.Lock()
		ipID := s.ipID
		s.ipID++
		s.mu.Unlock()

		ipHeader := buildIPv4Header(len(udpPayload), si.spoofSrcIP, si.clientIP, udpProto, 128, ipID, true)

		pkt := make([]byte, len(ipHeader)+len(udpPayload))
		copy(pkt, ipHeader)
		copy(pkt[len(ipHeader):], udpPayload)

		// Send via raw socket
		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], si.clientIP[:])
		sa.Port = int(si.clientPort)

		if err := syscall.Sendto(s.rawSockFd, pkt, 0, &sa); err != nil {
			errors.LogWarning(context.Background(), "qstunnel raw send error: ", err, " to ", si.clientIPStr, ":", si.clientPort)
		} else {
			errors.LogDebug(context.Background(), "qstunnel: spoofed pkt sent to ", si.clientIPStr, ":", si.clientPort, " from ", net.IP(si.spoofSrcIP[:]).String(), ":", si.spoofSrcPort, " len=", len(data))
		}
	}
}

// cleanLoop removes idle clients.
func (s *qstunnelConnServer) cleanLoop() {
	ticker := time.NewTicker(serverIdleTimeout / 2)
	defer ticker.Stop()
	for {
		if s.closed {
			return
		}
		<-ticker.C

		s.mu.Lock()
		now := time.Now()
		for key, cs := range s.clients {
			cs.mu.Lock()
			idle := now.Sub(cs.lastSeen) > serverIdleTimeout
			cs.mu.Unlock()
			if idle {
				cs.dataHandler.close()
				close(cs.writeQueue)
				delete(s.clients, key)
			}
		}
		s.mu.Unlock()
	}
}

func (s *qstunnelConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, ok := <-s.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(pkt.p) {
		errors.LogDebug(context.Background(), "qstunnel server read short buffer")
		return 0, pkt.addr, nil
	}
	copy(p, pkt.p)
	return len(pkt.p), pkt.addr, nil
}

func (s *qstunnelConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, io.ErrClosedPipe
	}

	// Find the client by address
	errors.LogDebug(context.Background(), "qstunnel: WriteTo len=", len(p), " addr=", addr, " clients=", len(s.clients))
	for _, cs := range s.clients {
		cs.mu.Lock()
		si := cs.sendInfo
		cs.mu.Unlock()

		if si == nil {
			continue
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		if si.clientIPStr == udpAddr.IP.String() && int(si.clientPort) == udpAddr.Port {
			buf := make([]byte, len(p))
			copy(buf, p)
			select {
			case cs.writeQueue <- buf:
				return len(p), nil
			default:
				return 0, nil
			}
		}
	}

	return 0, nil
}

func (s *qstunnelConnServer) Close() error {
	s.mu.Lock()
	s.closed = true
	for key, cs := range s.clients {
		cs.dataHandler.close()
		close(cs.writeQueue)
		delete(s.clients, key)
	}
	s.mu.Unlock()

	s.recvSock.Close()
	syscall.Close(s.rawSockFd)
	return s.conn.Close()
}

func (s *qstunnelConnServer) LocalAddr() net.Addr {
	return s.recvSock.LocalAddr()
}

func (s *qstunnelConnServer) SetDeadline(t time.Time) error {
	return s.recvSock.SetDeadline(t)
}

func (s *qstunnelConnServer) SetReadDeadline(t time.Time) error {
	return s.recvSock.SetReadDeadline(t)
}

func (s *qstunnelConnServer) SetWriteDeadline(t time.Time) error {
	return s.recvSock.SetWriteDeadline(t)
}

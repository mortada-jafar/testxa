package qstunnel

import (
	"encoding/binary"
)

const (
	udpProto   = 17
	ipv4VerIHL = 0x45
)

// internetChecksum computes the RFC 1071 internet checksum.
func internetChecksum(data []byte) uint16 {
	var s uint32
	n := len(data) &^ 1
	for i := 0; i < n; i += 2 {
		s += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)&1 != 0 {
		s += uint32(data[n]) << 8
	}
	s = (s & 0xFFFF) + (s >> 16)
	s = (s & 0xFFFF) + (s >> 16)
	return uint16(^s & 0xFFFF)
}

// buildUDPPayloadV4 constructs a UDP segment with proper checksum for IPv4.
func buildUDPPayloadV4(data []byte, srcPort, dstPort uint16, srcIP, dstIP [4]byte) []byte {
	udpLen := uint16(8 + len(data))

	// Build pseudo header for checksum
	pseudo := make([]byte, 12+8+len(data))
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = udpProto
	binary.BigEndian.PutUint16(pseudo[10:], udpLen)
	binary.BigEndian.PutUint16(pseudo[12:], srcPort)
	binary.BigEndian.PutUint16(pseudo[14:], dstPort)
	binary.BigEndian.PutUint16(pseudo[16:], udpLen)
	binary.BigEndian.PutUint16(pseudo[18:], 0) // checksum placeholder
	copy(pseudo[20:], data)

	cksum := internetChecksum(pseudo)
	if cksum == 0 {
		cksum = 0xFFFF
	}

	// Build actual UDP packet
	pkt := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(pkt[0:], srcPort)
	binary.BigEndian.PutUint16(pkt[2:], dstPort)
	binary.BigEndian.PutUint16(pkt[4:], udpLen)
	binary.BigEndian.PutUint16(pkt[6:], cksum)
	copy(pkt[8:], data)
	return pkt
}

// buildIPv4Header constructs an IPv4 header with proper checksum.
func buildIPv4Header(payloadLen int, srcIP, dstIP [4]byte, proto byte, ttl byte, ipID uint16, dontFragment bool) []byte {
	totalLen := uint16(20 + payloadLen)
	var flagsFrag uint16
	if dontFragment {
		flagsFrag = 0x2 << 13
	}

	hdr := make([]byte, 20)
	hdr[0] = ipv4VerIHL
	hdr[1] = 0 // DSCP/ECN
	binary.BigEndian.PutUint16(hdr[2:], totalLen)
	binary.BigEndian.PutUint16(hdr[4:], ipID)
	binary.BigEndian.PutUint16(hdr[6:], flagsFrag)
	hdr[8] = ttl
	hdr[9] = proto
	binary.BigEndian.PutUint16(hdr[10:], 0) // checksum placeholder
	copy(hdr[12:16], srcIP[:])
	copy(hdr[16:20], dstIP[:])

	cksum := internetChecksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:], cksum)

	return hdr
}

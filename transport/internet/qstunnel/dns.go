package qstunnel

import (
	"encoding/binary"
	"errors"
)

// encodeQName converts a domain string to DNS wire-format QNAME.
// e.g., "example.com" -> [7]example[3]com[0]
func encodeQName(domain []byte) []byte {
	var result []byte
	labels := splitDomain(domain)
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	result = append(result, 0)
	return result
}

// splitDomain splits a domain by '.' and returns labels.
func splitDomain(domain []byte) [][]byte {
	var labels [][]byte
	start := 0
	for i, b := range domain {
		if b == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}
	return labels
}

// labelDomain splits a domain into lowercased labels (for matching).
func labelDomain(domain []byte) [][]byte {
	labels := splitDomain(domain)
	for i, l := range labels {
		labels[i] = toLowerBytes(l)
	}
	return labels
}

func toLowerBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		} else {
			out[i] = c
		}
	}
	return out
}

// insertDots splits data into DNS label-encoded segments (length-prefixed, max maxSub bytes each).
func insertDots(data []byte, maxSub int) []byte {
	var out []byte
	for i := 0; i < len(data); i += maxSub {
		end := i + maxSub
		if end > len(data) {
			end = len(data)
		}
		seg := data[i:end]
		out = append(out, byte(len(seg)))
		out = append(out, seg...)
	}
	return out
}

// buildDNSQuery builds a DNS query packet.
func buildDNSQuery(qnameEncoded []byte, qID uint16, qtype uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], qID)
	binary.BigEndian.PutUint16(header[2:], 0x0100) // flags: recursion desired
	binary.BigEndian.PutUint16(header[4:], 1)       // QDCOUNT
	binary.BigEndian.PutUint16(header[6:], 0)       // ANCOUNT
	binary.BigEndian.PutUint16(header[8:], 0)       // NSCOUNT
	binary.BigEndian.PutUint16(header[10:], 0)      // ARCOUNT

	question := make([]byte, len(qnameEncoded)+4)
	copy(question, qnameEncoded)
	binary.BigEndian.PutUint16(question[len(qnameEncoded):], qtype)
	binary.BigEndian.PutUint16(question[len(qnameEncoded)+2:], 0x0001) // QCLASS IN

	result := make([]byte, 0, len(header)+len(question))
	result = append(result, header...)
	result = append(result, question...)
	return result
}

// parsedDNSQuery holds parsed DNS query data.
type parsedDNSQuery struct {
	QID          uint16
	QFlags       uint16
	Labels       [][]byte
	QType        uint16
	NextQuestion int // offset after the question section
}

// handleDNSRequest parses a DNS query and returns its components.
func handleDNSRequest(data []byte) (*parsedDNSQuery, error) {
	if len(data) < 17 {
		return nil, errors.New("packet too short")
	}

	qid := binary.BigEndian.Uint16(data[0:])
	qflags := binary.BigEndian.Uint16(data[2:])
	qdcount := binary.BigEndian.Uint16(data[4:])

	if qdcount != 1 {
		return nil, errors.New("not 1 question")
	}
	if qflags&0x8000 != 0 {
		return nil, errors.New("not a query")
	}

	labels, qtype, nextQuestion, err := handleQuestion(data, 12)
	if err != nil {
		return nil, err
	}

	return &parsedDNSQuery{
		QID:          qid,
		QFlags:       qflags,
		Labels:       labels,
		QType:        qtype,
		NextQuestion: nextQuestion,
	}, nil
}

// handleQuestion parses the question section of a DNS packet.
func handleQuestion(data []byte, offset int) ([][]byte, uint16, int, error) {
	var labels [][]byte
	lenData := len(data)
	for offset < lenData {
		labelLen := int(data[offset])
		if labelLen == 0 {
			if offset+5 > lenData {
				return nil, 0, 0, errors.New("truncated question")
			}
			qtype := binary.BigEndian.Uint16(data[offset+1:])
			qclass := binary.BigEndian.Uint16(data[offset+3:])
			if qclass != 1 {
				return nil, 0, 0, errors.New("invalid qclass")
			}
			nextQuestion := offset + 5
			return labels, qtype, nextQuestion, nil
		}
		if labelLen > 63 {
			return nil, 0, 0, errors.New("label too long")
		}
		labelStart := offset + 1
		offset = labelStart + labelLen
		if offset > lenData {
			return nil, 0, 0, errors.New("truncated label")
		}
		labels = append(labels, toLowerBytes(data[labelStart:offset]))
	}
	return nil, 0, 0, errors.New("unexpected end of question")
}

// createNoerrorEmptyResponse creates a NOERROR DNS response with no answer records.
func createNoerrorEmptyResponse(qid uint16, qflags uint16, question []byte) []byte {
	rflags := uint16(0x8400) | (qflags & 0x7910)
	if qflags&0x7800 != 0 {
		rflags |= 0x0004
	}

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], qid)
	binary.BigEndian.PutUint16(header[2:], rflags)
	binary.BigEndian.PutUint16(header[4:], 1) // QDCOUNT
	binary.BigEndian.PutUint16(header[6:], 0)
	binary.BigEndian.PutUint16(header[8:], 0)
	binary.BigEndian.PutUint16(header[10:], 0)

	result := make([]byte, 0, len(header)+len(question))
	result = append(result, header...)
	result = append(result, question...)
	return result
}

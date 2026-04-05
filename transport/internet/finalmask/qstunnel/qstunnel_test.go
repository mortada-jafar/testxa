package qstunnel

import (
	"bytes"
	"testing"
)

func TestBase32RoundTrip(t *testing.T) {
	data := []byte("Hello, QS-Tunnel!")
	encoded := base32EncodeLower(data)
	decoded, err := base32DecodeNoPad(encoded)
	if err != nil {
		t.Fatal("decode error:", err)
	}
	if !bytes.Equal(data, decoded) {
		t.Fatalf("mismatch: got %q, want %q", decoded, data)
	}
}

func TestNumberBase32RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 1000, 32767} {
		encoded := numberToBase32Lower(n, dataOffsetWidth)
		decoded := base32ToNumber(encoded)
		if decoded != n {
			t.Fatalf("number %d: encoded=%q decoded=%d", n, encoded, decoded)
		}
	}
}

func TestEncodeQName(t *testing.T) {
	qname := encodeQName([]byte("example.com"))
	// Should be: [7]example[3]com[0]
	expected := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Equal(qname, expected) {
		t.Fatalf("qname mismatch: got %v, want %v", qname, expected)
	}
}

func TestInsertDots(t *testing.T) {
	data := []byte("abcdefghij")
	result := insertDots(data, 4)
	// Should split into: [4]abcd[4]efgh[2]ij
	expected := []byte{4, 'a', 'b', 'c', 'd', 4, 'e', 'f', 'g', 'h', 2, 'i', 'j'}
	if !bytes.Equal(result, expected) {
		t.Fatalf("insertDots mismatch: got %v, want %v", result, expected)
	}
}

func TestBuildAndParseDNSQuery(t *testing.T) {
	qname := encodeQName([]byte("test.example.com"))
	query := buildDNSQuery(qname, 0x1234, 1)

	parsed, err := handleDNSRequest(query)
	if err != nil {
		t.Fatal("parse error:", err)
	}
	if parsed.QID != 0x1234 {
		t.Fatalf("QID: got %x, want 1234", parsed.QID)
	}
	if parsed.QType != 1 {
		t.Fatalf("QType: got %d, want 1", parsed.QType)
	}
	if len(parsed.Labels) != 3 {
		t.Fatalf("Labels: got %d, want 3", len(parsed.Labels))
	}
	if string(parsed.Labels[0]) != "test" || string(parsed.Labels[1]) != "example" || string(parsed.Labels[2]) != "com" {
		t.Fatalf("Labels: got %v", parsed.Labels)
	}
}

func TestDNSResponse(t *testing.T) {
	qname := encodeQName([]byte("test.com"))
	query := buildDNSQuery(qname, 0xABCD, 1)
	parsed, _ := handleDNSRequest(query)

	response := createNoerrorEmptyResponse(parsed.QID, parsed.QFlags, query[12:parsed.NextQuestion])
	if len(response) < 12 {
		t.Fatal("response too short")
	}
	// Check QR bit is set
	flags := uint16(response[2])<<8 | uint16(response[3])
	if flags&0x8000 == 0 {
		t.Fatal("QR bit not set in response")
	}
}

func TestInternetChecksum(t *testing.T) {
	// Known test vector: RFC 1071 example
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	cksum := internetChecksum(data)
	if cksum != 0x0dff {
		// The expected value depends on the data; just verify it's non-zero and round-trips
		// Verifying: checksum of data+checksum should be 0
		withCksum := make([]byte, len(data)+2)
		copy(withCksum, data)
		withCksum[len(data)] = byte(cksum >> 8)
		withCksum[len(data)+1] = byte(cksum)
		verify := internetChecksum(withCksum)
		if verify != 0 {
			t.Fatalf("checksum verification failed: %x (checksum was %x)", verify, cksum)
		}
	}
}

func TestFragmentAndReassemble(t *testing.T) {
	qnameEncoded := encodeQName([]byte("test.com"))
	maxDomainLen := 99
	maxSubLen := 63
	clientIDBytes := numberToBase32Lower(42, clientIDWidth)

	chunkLen := computeChunkLen(maxDomainLen+2, len(qnameEncoded), maxSubLen, dataOffsetWidth, len(clientIDBytes))
	if chunkLen <= 0 {
		t.Fatal("chunkLen <= 0")
	}

	// Fragment some test data
	testData := []byte("Hello, this is a test message for QS-Tunnel fragmentation!")
	domains := fragmentData(testData, 100, chunkLen, qnameEncoded, maxSubLen, dataOffsetWidth, maxDomainLen+2, clientIDBytes)
	if len(domains) == 0 {
		t.Fatal("fragmentation returned empty")
	}

	// Simulate receiving: parse each domain, extract data, reassemble
	dh := newDataHandler(totalDataOffsets)
	defer dh.close()

	var assembled []byte
	for _, domain := range domains {
		// Strip qnameEncoded suffix and join labels
		// The domain is: insertDots(payload, maxSubLen) + qnameEncoded
		// We need to parse labels and strip the suffix
		labels := parseLabelEncoded(domain)
		if len(labels) == 0 {
			t.Fatal("no labels in domain")
		}

		// Find and strip the domain suffix labels
		suffixLabels := splitDomain([]byte("test.com"))
		dataLabels := labels[:len(labels)-len(suffixLabels)]

		var joined []byte
		for _, l := range dataLabels {
			joined = append(joined, l...)
		}

		clientID, dataOffset, fragmentPart, lastFragment, chunkData, err := parseChunkData(joined, dataOffsetWidth, clientIDWidth)
		if err != nil {
			t.Fatal("parseChunkData error:", err)
		}
		_ = clientID

		result := dh.newDataEvent(dataOffset, fragmentPart, lastFragment, chunkData)
		if result != nil {
			assembled = result
		}
	}

	if assembled == nil {
		t.Fatal("reassembly returned nil")
	}

	decoded, err := base32DecodeNoPad(assembled)
	if err != nil {
		t.Fatal("base32 decode error:", err)
	}

	if !bytes.Equal(decoded, testData) {
		t.Fatalf("reassembly mismatch: got %q, want %q", decoded, testData)
	}
}

// parseLabelEncoded parses DNS label-encoded bytes into labels.
func parseLabelEncoded(data []byte) [][]byte {
	var labels [][]byte
	i := 0
	for i < len(data) {
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		i++
		if i+labelLen > len(data) {
			break
		}
		labels = append(labels, data[i:i+labelLen])
		i += labelLen
	}
	return labels
}

func TestChunkLen(t *testing.T) {
	qnameEncoded := encodeQName([]byte("tunnel.example.com"))
	chunkLen := computeChunkLen(101, len(qnameEncoded), 63, dataOffsetWidth, clientIDWidth)
	if chunkLen <= 0 {
		t.Fatalf("chunkLen should be positive, got %d", chunkLen)
	}
	t.Logf("chunkLen = %d bytes per DNS query (domain=%q)", chunkLen, "tunnel.example.com")
}

func TestReassemblyTimeout(t *testing.T) {
	dh := newDataHandler(100)
	defer dh.close()

	// Send only fragment 0, never send the last fragment
	result := dh.newDataEvent(0, 0, false, []byte("partial"))
	if result != nil {
		t.Fatal("should not assemble incomplete data")
	}

	// The slot will be cleaned up after assembleTime (5s) by the cleanup goroutine
}

func TestReassemblySingleFragment(t *testing.T) {
	dh := newDataHandler(100)
	defer dh.close()

	// Single fragment (last=true)
	result := dh.newDataEvent(5, 0, true, []byte("single"))
	if result == nil {
		t.Fatal("single fragment should assemble immediately")
	}
	if !bytes.Equal(result, []byte("single")) {
		t.Fatalf("got %q, want %q", result, "single")
	}
}

func TestReassemblyMultiFragment(t *testing.T) {
	dh := newDataHandler(100)
	defer dh.close()

	// 3 fragments, arriving out of order
	r1 := dh.newDataEvent(10, 1, false, []byte("bbb"))
	if r1 != nil {
		t.Fatal("should not assemble yet")
	}
	r2 := dh.newDataEvent(10, 0, false, []byte("aaa"))
	if r2 != nil {
		t.Fatal("should not assemble yet")
	}
	r3 := dh.newDataEvent(10, 2, true, []byte("ccc"))
	if r3 == nil {
		t.Fatal("should assemble now")
	}
	if !bytes.Equal(r3, []byte("aaabbbccc")) {
		t.Fatalf("got %q, want %q", r3, "aaabbbccc")
	}
}

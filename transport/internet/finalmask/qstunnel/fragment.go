package qstunnel

// computeMaxM finds maximum m such that: m + ceil(m / s) <= maxAllowed
func computeMaxM(s, maxAllowed int) int {
	if maxAllowed <= 0 {
		return 0
	}
	q := maxAllowed / (s + 1)
	remaining := maxAllowed - q*(s+1)
	r := remaining - 1
	if r < 0 {
		r = 0
	}
	return q*s + r
}

// computeChunkLen calculates the max payload per DNS query.
func computeChunkLen(maxEncodedDomainLen, qnameEncodedLen, maxSubLen, dataOffsetWidth, clientIDWidth int) int {
	maxAllowed := maxEncodedDomainLen - qnameEncodedLen
	m := computeMaxM(maxSubLen, maxAllowed)
	chunkLen := m - clientIDWidth - dataOffsetWidth - 2 // fragment_part_width=2
	return chunkLen
}

// fragmentResult holds a single DNS query domain (label-encoded).
type fragmentResult struct {
	domain []byte
}

// fragmentData fragments data into DNS label-encoded domains for transmission.
// Returns a list of label-encoded domain bytes ready to prepend to qnameEncoded.
//
// Wire format per fragment:
//
//	[clientID][dataOffset][fragmentIndex][magic][chunkData]
//
// magic: '0' = not-last, fragment<32; '1' = last, fragment<32;
//
//	'8' = not-last, fragment>=32; '9' = last, fragment>=32
func fragmentData(
	data []byte,
	dataOffset int,
	chunkLen int,
	qnameEncoded []byte,
	maxSubLen int,
	dataOffsetWidth int,
	maxEncodedDomainLen int,
	clientIDBytes []byte,
) [][]byte {
	encoded := base32EncodeLower(data)
	numChunks := (len(encoded) + chunkLen - 1) / chunkLen
	if numChunks > 64 {
		return nil // too large
	}

	dataOffsetBytes := numberToBase32Lower(dataOffset, dataOffsetWidth)
	var domains [][]byte

	for i := 0; i < numChunks; i++ {
		start := i * chunkLen
		end := start + chunkLen
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[start:end]

		isLast := (end >= len(encoded))
		fragIndex := i & 31
		fragHigh := i & 32

		var magic byte
		if fragHigh != 0 {
			if isLast {
				magic = '9'
			} else {
				magic = '8'
			}
		} else {
			if isLast {
				magic = '1'
			} else {
				magic = '0'
			}
		}

		// Build: [clientID][dataOffset][fragChar][magic][chunk]
		var payload []byte
		payload = append(payload, clientIDBytes...)
		payload = append(payload, dataOffsetBytes...)
		payload = append(payload, base32Chars[fragIndex])
		payload = append(payload, magic)
		payload = append(payload, chunk...)

		domain := insertDots(payload, maxSubLen)
		domain = append(domain, qnameEncoded...)
		domains = append(domains, domain)
	}

	return domains
}

// parseChunkData parses a received fragment from joined label data.
// Returns clientID, dataOffset, fragmentPart, lastFragment, chunkData.
func parseChunkData(data []byte, dataOffsetWidth, clientIDWidth int) (
	clientID []byte, dataOffset int, fragmentPart int, lastFragment bool, chunkData []byte, err error,
) {
	minLen := clientIDWidth + dataOffsetWidth + 2
	if len(data) < minLen {
		return nil, 0, 0, false, nil, errInvalidFragment
	}

	if clientIDWidth > 0 {
		clientID = data[:clientIDWidth]
		fpIndex := clientIDWidth + dataOffsetWidth
		dataOffset = base32ToNumber(data[clientIDWidth:fpIndex])

		fragRaw := base32Lookup[data[fpIndex]]
		if fragRaw < 0 {
			return nil, 0, 0, false, nil, errInvalidFragment
		}

		magic := data[fpIndex+1]
		fragmentPart, lastFragment = decodeMagic(fragRaw, magic)
		if fragmentPart < 0 {
			return nil, 0, 0, false, nil, errInvalidFragment
		}

		chunkData = data[fpIndex+2:]
	} else {
		fpIndex := dataOffsetWidth
		dataOffset = base32ToNumber(data[:fpIndex])

		fragRaw := base32Lookup[data[fpIndex]]
		if fragRaw < 0 {
			return nil, 0, 0, false, nil, errInvalidFragment
		}

		magic := data[fpIndex+1]
		fragmentPart, lastFragment = decodeMagic(fragRaw, magic)
		if fragmentPart < 0 {
			return nil, 0, 0, false, nil, errInvalidFragment
		}

		chunkData = data[fpIndex+2:]
	}

	return
}

func decodeMagic(fragRaw int, magic byte) (int, bool) {
	switch magic {
	case '0':
		return fragRaw, false
	case '1':
		return fragRaw, true
	case '8':
		return fragRaw | 32, false
	case '9':
		return fragRaw | 32, true
	default:
		return -1, false
	}
}

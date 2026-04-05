package qstunnel

import (
	"encoding/base32"
	"strings"
)

var b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"

var base32Lookup [256]int

func init() {
	for i := range base32Lookup {
		base32Lookup[i] = -1
	}
	for i, ch := range base32Chars {
		base32Lookup[ch] = i
		upper := ch - 32 // uppercase
		if upper >= 'A' && upper <= 'Z' {
			base32Lookup[upper] = i
		}
	}
	// digits 2-7 uppercase same as lowercase
}

// base32EncodeLower encodes data to lowercase base32 without padding.
func base32EncodeLower(data []byte) []byte {
	s := b32Encoding.EncodeToString(data)
	return []byte(strings.ToLower(s))
}

// base32DecodeNoPad decodes base32 data without padding (case-insensitive).
func base32DecodeNoPad(data []byte) ([]byte, error) {
	s := strings.ToUpper(string(data))
	return b32Encoding.DecodeString(s)
}

// numberToBase32Lower converts an integer to a fixed-width lowercase base32 string.
func numberToBase32Lower(n int, width int) []byte {
	result := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		result[i] = base32Chars[n&31]
		n >>= 5
	}
	return result
}

// base32ToNumber converts a base32 string to an integer.
func base32ToNumber(s []byte) int {
	value := 0
	for _, ch := range s {
		idx := base32Lookup[ch]
		if idx < 0 {
			return -1
		}
		value = (value << 5) + idx
	}
	return value
}

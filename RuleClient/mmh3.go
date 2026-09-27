package RuleClient

import (
	"encoding/base64"
	"math/bits"
	"strconv"
	"strings"
)

// mmh3 implements the MurmurHash3 x86 32-bit hash with seed 0, used for
// favicon fingerprinting with the fofa convention: hash = mmh3(base64(bytes)).
func mmh3(data []byte) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	var h1 uint32 = 0

	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	tail := nblocks * 4
	switch len(data) & 3 {
	case 3:
		k1 ^= uint32(data[tail+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(data[tail+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(data[tail])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// faviconFofaHash computes the fofa-style favicon hash (mmh3 of the base64
// encoded icon bytes), matching the hash values in the fingerprint YAML.
func faviconFofaHash(icon []byte) uint32 {
	return mmh3([]byte(base64.StdEncoding.EncodeToString(icon)))
}

// faviconHashMatch reports whether a computed favicon hash matches one of the
// YAML values, accepting both the signed and unsigned int32 representations.
func faviconHashMatch(hash uint32, values []string) bool {
	for _, v := range values {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		if int64(int32(hash)) == n || int64(hash) == n {
			return true
		}
	}
	return false
}

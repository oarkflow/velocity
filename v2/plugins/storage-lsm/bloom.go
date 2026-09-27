package lsm

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"hash/fnv"
	"math"
)

// bloomFilter is a standard fixed-size bit-array Bloom filter using double
// hashing (h1 + i*h2) to derive k independent hash positions from two real
// hash functions, avoiding the cost of k separate hash computations. Ported
// in spirit from v1's filter.go (same purpose: let an SSTable lookup skip a
// disk read for a key it definitely does not contain).
type bloomFilter struct {
	bits      []byte
	numBits   uint32
	numHashes uint8
}

// newBloomFilter sizes a filter for expectedItems entries at the given
// target false-positive rate using the standard optimal-m/optimal-k
// formulas.
func newBloomFilter(expectedItems int, falsePositiveRate float64) *bloomFilter {
	if expectedItems <= 0 {
		expectedItems = 1
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = 0.01
	}
	m := optimalNumBits(expectedItems, falsePositiveRate)
	k := optimalNumHashes(m, expectedItems)
	return &bloomFilter{bits: make([]byte, (m+7)/8), numBits: m, numHashes: k}
}

func optimalNumBits(n int, p float64) uint32 {
	m := -1 * float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)
	if m < 8 {
		m = 8
	}
	return uint32(math.Ceil(m))
}

func optimalNumHashes(m uint32, n int) uint8 {
	k := float64(m) / float64(n) * math.Ln2
	if k < 1 {
		k = 1
	}
	if k > 30 {
		k = 30
	}
	return uint8(math.Round(k))
}

func hashPair(key []byte) (uint32, uint32) {
	h := fnv.New32a()
	h.Write(key)
	h1 := h.Sum32()
	h2 := crc32.ChecksumIEEE(key)
	if h2 == 0 {
		h2 = 0x9e3779b9 // avoid a degenerate all-zero second hash
	}
	return h1, h2
}

func (b *bloomFilter) add(key []byte) {
	h1, h2 := hashPair(key)
	for i := uint8(0); i < b.numHashes; i++ {
		bit := (h1 + uint32(i)*h2) % b.numBits
		b.bits[bit/8] |= 1 << (bit % 8)
	}
}

// mayContain returns false only when key is DEFINITELY absent (the
// standard Bloom filter guarantee: no false negatives, possible false
// positives).
func (b *bloomFilter) mayContain(key []byte) bool {
	h1, h2 := hashPair(key)
	for i := uint8(0); i < b.numHashes; i++ {
		bit := (h1 + uint32(i)*h2) % b.numBits
		if b.bits[bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

func (b *bloomFilter) encode() []byte {
	buf := make([]byte, 4+1+len(b.bits))
	binary.BigEndian.PutUint32(buf[0:4], b.numBits)
	buf[4] = b.numHashes
	copy(buf[5:], b.bits)
	return buf
}

func decodeBloomFilter(data []byte) (*bloomFilter, error) {
	if len(data) < 5 {
		return nil, errors.New("lsm: bloom filter data too short")
	}
	numBits := binary.BigEndian.Uint32(data[0:4])
	numHashes := data[4]
	bits := make([]byte, len(data)-5)
	copy(bits, data[5:])
	return &bloomFilter{bits: bits, numBits: numBits, numHashes: numHashes}, nil
}

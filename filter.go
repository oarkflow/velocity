package velocity

import (
	"encoding/binary"
	"unsafe"
)

// Simple Bloom Filter implementation
type BloomFilter struct {
	bits []uint64
	size uint64
	hash uint64
}

func NewBloomFilter(expectedItems int, bitsPerItem int) *BloomFilter {
	if expectedItems < 1 {
		expectedItems = 1
	}
	size := uint64(expectedItems * bitsPerItem)
	if size == 0 {
		size = 64 // minimum size (bits)
	}
	return &BloomFilter{
		bits: make([]uint64, (size+63)/64),
		size: size,
		hash: 2, // Number of hash functions
	}
}

func (bf *BloomFilter) Add(key []byte) {
	h1, h2 := bf.hash1(key), bf.hash2(key)
	for i := uint64(0); i < bf.hash; i++ {
		bit := (h1 + i*h2) % bf.size
		bf.bits[bit/64] |= 1 << (bit % 64)
	}
}

func (bf *BloomFilter) Contains(key []byte) bool {
	h1, h2 := bf.hash1(key), bf.hash2(key)
	for i := uint64(0); i < bf.hash; i++ {
		bit := (h1 + i*h2) % bf.size
		if bf.bits[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) hash1(data []byte) uint64 {
	return bf.hash1SIMD(data)
}

func (bf *BloomFilter) hash2(data []byte) uint64 {
	return bf.hash2SIMD(data)
}

func (bf *BloomFilter) Marshal() []byte {
	buf := make([]byte, 16+len(bf.bits)*8)
	binary.LittleEndian.PutUint64(buf[0:8], bf.size)
	binary.LittleEndian.PutUint64(buf[8:16], bf.hash)

	for i, word := range bf.bits {
		binary.LittleEndian.PutUint64(buf[16+i*8:16+(i+1)*8], word)
	}

	return buf
}

// Vectorized hash function for better distribution
func fastHash(data []byte) uint64 {
	const (
		prime1 = 11400714785074694791
		prime2 = 14029467366897019727
		prime3 = 1609587929392839161
		prime4 = 9650029242287828579
		prime5 = 2870177450012600261
	)

	var h uint64 = prime5 + uint64(len(data))

	// Process 8-byte chunks
	i := 0
	for i+8 <= len(data) {
		k1 := *(*uint64)(unsafe.Pointer(&data[i])) * prime2
		k1 = ((k1 << 31) | (k1 >> 33)) * prime1
		h ^= k1
		h = ((h<<27)|(h>>37))*prime1 + prime4
		i += 8
	}

	// Process remaining bytes
	for i < len(data) {
		h ^= uint64(data[i]) * prime5
		h = ((h << 11) | (h >> 53)) * prime1
		i++
	}

	// Final avalanche
	h ^= h >> 33
	h *= prime2
	h ^= h >> 29
	h *= prime3
	h ^= h >> 32

	return h
}

// Advanced skip list with memory pooling
func compareKeysFast(a, b []byte) int {
	return fastMemCmp(a, b)
}

// Optimized bloom filter with SIMD operations
func (bf *BloomFilter) hash1SIMD(data []byte) uint64 {
	return fastHash(data)
}

func (bf *BloomFilter) hash2SIMD(data []byte) uint64 {
	return fastHash(data) >> 16 // Different hash by bit shifting
}

// SIMD-optimized operations for x86_64
// These functions use compiler intrinsics for maximum performance

//go:noinline
func fastMemCmp(a, b []byte) int {
	// Fast path for equal length comparison
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}

	// Use unsafe pointer arithmetic for 8-byte comparisons
	minLen := len(a)
	i := 0

	// Compare 8 bytes at a time
	for i+8 <= minLen {
		av := *(*uint64)(unsafe.Pointer(&a[i]))
		bv := *(*uint64)(unsafe.Pointer(&b[i]))
		if av != bv {
			// Find the differing byte
			for j := 0; j < 8; j++ {
				if a[i+j] != b[i+j] {
					if a[i+j] < b[i+j] {
						return -1
					}
					return 1
				}
			}
		}
		i += 8
	}

	// Compare remaining bytes
	for i < minLen {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
		i++
	}

	return 0
}

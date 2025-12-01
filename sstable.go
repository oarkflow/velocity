package velocity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
	"unsafe"
)

// SSTable for persistent storage
type SSTable struct {
	file        *os.File
	mmap        []byte
	indexData   []IndexEntry
	bloomFilter *BloomFilter
	minKey      []byte
	maxKey      []byte
	crypto      *CryptoProvider
}

type IndexEntry struct {
	Key    []byte
	Offset uint64
	Size   uint32
}

func NewSSTable(path string, entries []*Entry, crypto *CryptoProvider) (*SSTable, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if crypto == nil {
		return nil, fmt.Errorf("encryption provider is required for SSTable")
	}

	// Sort entries by key
	sort.Slice(entries, func(i, j int) bool {
		return compareKeys(entries[i].Key, entries[j].Key) < 0
	})

	// Create bloom filter
	bf := NewBloomFilter(len(entries), DefaultBloomFilterBits)
	for _, entry := range entries {
		bf.Add(entry.Key)
	}

	// Write header
	header := struct {
		Magic       uint32
		Version     uint32
		EntryCount  uint32
		IndexOffset uint64
		BloomOffset uint64
		BloomSize   uint32
	}{
		Magic:      MagicNumber,
		Version:    Version,
		EntryCount: uint32(len(entries)),
	}

	binary.Write(file, binary.LittleEndian, header)

	// Write data blocks and build index
	var indexEntries []IndexEntry
	currentOffset := uint64(unsafe.Sizeof(header))

	for _, entry := range entries {
		keyLen := uint32(len(entry.Key))
		nonce, ciphertext, err := crypto.Encrypt(entry.Value, buildEntryAAD(entry.Key, entry.Timestamp, entry.Deleted))
		if err != nil {
			return nil, err
		}
		valueLen := uint32(len(ciphertext))
		nonceLen := uint16(len(nonce))

		startOffset := currentOffset

		// Write entry
		binary.Write(file, binary.LittleEndian, keyLen)
		file.Write(entry.Key)
		binary.Write(file, binary.LittleEndian, nonceLen)
		file.Write(nonce)
		binary.Write(file, binary.LittleEndian, valueLen)
		file.Write(ciphertext)
		binary.Write(file, binary.LittleEndian, entry.Timestamp)

		var deleted uint8
		if entry.Deleted {
			deleted = 1
		}
		binary.Write(file, binary.LittleEndian, deleted)
		binary.Write(file, binary.LittleEndian, entry.checksum)

		entrySize := 4 + len(entry.Key) + 2 + len(nonce) + 4 + len(ciphertext) + 8 + 1 + 4
		currentOffset += uint64(entrySize)

		indexEntries = append(indexEntries, IndexEntry{
			Key:    append([]byte{}, entry.Key...),
			Offset: startOffset,
			Size:   uint32(entrySize),
		})
	}

	// Write bloom filter
	bloomOffset := currentOffset
	bloomData := bf.Marshal()
	file.Write(bloomData)
	currentOffset += uint64(len(bloomData))

	// Write index
	indexOffset := currentOffset
	for _, idxEntry := range indexEntries {
		keyLen := uint32(len(idxEntry.Key))
		binary.Write(file, binary.LittleEndian, keyLen)
		file.Write(idxEntry.Key)
		binary.Write(file, binary.LittleEndian, idxEntry.Offset)
		binary.Write(file, binary.LittleEndian, idxEntry.Size)
	}

	// Update header with offsets
	file.Seek(0, io.SeekStart)
	header.IndexOffset = indexOffset
	header.BloomOffset = bloomOffset
	header.BloomSize = uint32(len(bloomData))
	binary.Write(file, binary.LittleEndian, header)

	// Memory map the file for fast reads
	stat, _ := file.Stat()
	mmap, err := syscall.Mmap(int(file.Fd()), 0, int(stat.Size()),
		syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		file.Close()
		return nil, err
	}

	sst := &SSTable{
		file:        file,
		mmap:        mmap,
		indexData:   indexEntries,
		bloomFilter: bf,
		crypto:      crypto,
	}

	if len(entries) > 0 {
		sst.minKey = append([]byte{}, entries[0].Key...)
		sst.maxKey = append([]byte{}, entries[len(entries)-1].Key...)
	}

	return sst, nil
}

func (sst *SSTable) Get(key []byte) (*Entry, error) {
	// Check bloom filter first
	if !sst.bloomFilter.Contains(key) {
		return nil, nil
	}

	// Binary search in index
	idx := sort.Search(len(sst.indexData), func(i int) bool {
		return compareKeys(sst.indexData[i].Key, key) >= 0
	})

	if idx >= len(sst.indexData) || compareKeys(sst.indexData[idx].Key, key) != 0 {
		return nil, nil
	}

	// Read entry from mmap
	offset := sst.indexData[idx].Offset
	data := sst.mmap[offset:]

	var keyLen, valueLen uint32
	var timestamp uint64
	var deleted uint8
	var checksum uint32
	var nonceLen uint16

	reader := bytes.NewReader(data)
	binary.Read(reader, binary.LittleEndian, &keyLen)

	entryKey := make([]byte, keyLen)
	reader.Read(entryKey)

	binary.Read(reader, binary.LittleEndian, &nonceLen)
	nonce := make([]byte, nonceLen)
	reader.Read(nonce)

	binary.Read(reader, binary.LittleEndian, &valueLen)
	ciphertext := make([]byte, valueLen)
	reader.Read(ciphertext)

	binary.Read(reader, binary.LittleEndian, &timestamp)
	binary.Read(reader, binary.LittleEndian, &deleted)
	binary.Read(reader, binary.LittleEndian, &checksum)

	plaintext, err := sst.crypto.Decrypt(nonce, ciphertext, buildEntryAAD(entryKey, timestamp, deleted == 1))
	if err != nil {
		return nil, err
	}

	entry := &Entry{
		Key:       entryKey,
		Value:     plaintext,
		Timestamp: timestamp,
		Deleted:   deleted == 1,
		checksum:  checksum,
	}

	return entry, nil
}

func (sst *SSTable) Close() error {
	syscall.Munmap(sst.mmap)
	return sst.file.Close()
}

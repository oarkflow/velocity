package velocity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// SSTable for persistent storage
type SSTable struct {
	file *os.File
	mmap []byte
	// indexData is kept only for small SSTables; large tables use a sparse on-disk index
	indexData          []IndexEntry
	indexOffset        uint64   // offset of index region in the mmap
	entryCount         int      // number of entries in the index
	indexSampleOffsets []uint32 // sparse index: offsets (relative to indexOffset) for sampling
	bloomFilter        *BloomFilter
	minKey             []byte
	maxKey             []byte
	crypto             *CryptoProvider
}

type IndexEntry struct {
	Key    []byte
	Offset uint64
	Size   uint32
}

func NewSSTable(path string, entries []*Entry, crypto *CryptoProvider) (*SSTable, error) {
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

	// Create temp file in the same directory to ensure atomic rename
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return nil, err
	}
	defer func() {
		// If the temp file still exists (on failure), try to remove it
		_ = os.Remove(tmpFile.Name())
	}()

	// Write header placeholder
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

	if err := binary.Write(tmpFile, binary.LittleEndian, header); err != nil {
		tmpFile.Close()
		return nil, err
	}

	// Get the current offset after header
	curOff, err := tmpFile.Seek(0, io.SeekCurrent)
	if err != nil {
		tmpFile.Close()
		return nil, err
	}
	currentOffset := uint64(curOff)

	// Write data blocks and build index
	var indexEntries []IndexEntry
	for _, entry := range entries {
		// Ensure a checksum exists for the entry (use default CRC32 if not provided)
		if entry.checksum == 0 {
			if entry.Deleted {
				entry.checksum = crc32.ChecksumIEEE(entry.Key)
			} else {
				entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
			}
		}

		keyLen := uint32(len(entry.Key))
		nonce, ciphertext, err := crypto.Encrypt(entry.Value, buildEntryAAD(entry.Key, entry.Timestamp, entry.Deleted))
		if err != nil {
			tmpFile.Close()
			return nil, err
		}
		valueLen := uint32(len(ciphertext))
		nonceLen := uint16(len(nonce))

		startOffset := currentOffset

		// Write entry
		if err := binary.Write(tmpFile, binary.LittleEndian, keyLen); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if _, err := tmpFile.Write(entry.Key); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, nonceLen); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if _, err := tmpFile.Write(nonce); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, valueLen); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if _, err := tmpFile.Write(ciphertext); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, entry.Timestamp); err != nil {
			tmpFile.Close()
			return nil, err
		}

		var deleted uint8
		if entry.Deleted {
			deleted = 1
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, deleted); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, entry.checksum); err != nil {
			tmpFile.Close()
			return nil, err
		}

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
	if _, err := tmpFile.Write(bloomData); err != nil {
		tmpFile.Close()
		return nil, err
	}
	currentOffset += uint64(len(bloomData))

	// Write index
	indexOffset := currentOffset
	for _, idxEntry := range indexEntries {
		keyLen := uint32(len(idxEntry.Key))
		if err := binary.Write(tmpFile, binary.LittleEndian, keyLen); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if _, err := tmpFile.Write(idxEntry.Key); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, idxEntry.Offset); err != nil {
			tmpFile.Close()
			return nil, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, idxEntry.Size); err != nil {
			tmpFile.Close()
			return nil, err
		}
	}

	// Update header with offsets
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		tmpFile.Close()
		return nil, err
	}
	header.IndexOffset = indexOffset
	header.BloomOffset = bloomOffset
	header.BloomSize = uint32(len(bloomData))
	if err := binary.Write(tmpFile, binary.LittleEndian, header); err != nil {
		tmpFile.Close()
		return nil, err
	}

	// Ensure everything is flushed to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return nil, err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, err
	}

	// Atomically rename into place
	if err := os.Rename(tmpFile.Name(), path); err != nil {
		return nil, err
	}

	// Memory map the final file for fast reads
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, _ := file.Stat()
	mmap, err := syscall.Mmap(int(file.Fd()), 0, int(stat.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
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

// readIndexEntryAt reads an index entry starting at idxOffset bytes (relative to sst.indexOffset)
func (sst *SSTable) readIndexEntryAt(idxOffset uint32) (IndexEntry, error) {
	start := sst.indexOffset + uint64(idxOffset)
	if int(start) >= len(sst.mmap) {
		return IndexEntry{}, fmt.Errorf("index offset out of range")
	}
	reader := bytes.NewReader(sst.mmap[start:])
	var keyLen uint32
	if err := binary.Read(reader, binary.LittleEndian, &keyLen); err != nil {
		return IndexEntry{}, err
	}
	key := make([]byte, keyLen)
	if _, err := reader.Read(key); err != nil {
		return IndexEntry{}, err
	}
	var off uint64
	var size uint32
	if err := binary.Read(reader, binary.LittleEndian, &off); err != nil {
		return IndexEntry{}, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
		return IndexEntry{}, err
	}
	return IndexEntry{Key: append([]byte{}, key...), Offset: off, Size: size}, nil
}

// findIndexForKey uses a sparse sample index to locate the index entry for key without materializing the full index
func (sst *SSTable) findIndexForKey(key []byte) (*IndexEntry, bool, error) {
	// Fast path: fully materialized index
	if sst.indexData != nil {
		idx := sort.Search(len(sst.indexData), func(i int) bool {
			return compareKeys(sst.indexData[i].Key, key) >= 0
		})
		if idx >= len(sst.indexData) || compareKeys(sst.indexData[idx].Key, key) != 0 {
			return nil, false, nil
		}
		entry := sst.indexData[idx]
		return &entry, true, nil
	}

	// If we have sample offsets, do a binary search on samples to narrow the scan range
	if len(sst.indexSampleOffsets) > 0 {
		low := 0
		high := len(sst.indexSampleOffsets) - 1
		var samplePos int
		for low <= high {
			mid := (low + high) / 2
			off := sst.indexSampleOffsets[mid]
			sampleEntry, err := sst.readIndexEntryAt(off)
			if err != nil {
				return nil, false, err
			}
			cmp := compareKeys(sampleEntry.Key, key)
			if cmp == 0 {
				return &sampleEntry, true, nil
			}
			if cmp < 0 {
				samplePos = mid
				low = mid + 1
			} else {
				high = mid - 1
			}
		}

		// Start scanning from the chosen sample offset (or beginning if samplePos == 0)
		startOff := uint32(0)
		if samplePos < len(sst.indexSampleOffsets) {
			startOff = sst.indexSampleOffsets[samplePos]
		}
		// Scan forward until we find the key or pass it
		idxPos := startOff
		scanned := 0
		for scanned < sst.entryCount { // conservative bound
			entry, err := sst.readIndexEntryAt(idxPos)
			if err != nil {
				return nil, false, err
			}
			cmp := compareKeys(entry.Key, key)
			if cmp == 0 {
				return &entry, true, nil
			}
			if cmp > 0 {
				return nil, false, nil
			}
			idxEntrySize := 4 + len(entry.Key) + 8 + 4
			idxPos += uint32(idxEntrySize)
			scanned++
		}

		return nil, false, nil
	}

	// Linear scan across index region — correct and safe fallback when sparse index logic is not available.
	idxPos := uint32(0)
	for i := 0; i < sst.entryCount; i++ {
		entry, err := sst.readIndexEntryAt(idxPos)
		if err != nil {
			return nil, false, err
		}
		cmp := compareKeys(entry.Key, key)
		if cmp == 0 {
			return &entry, true, nil
		}
		if cmp > 0 {
			return nil, false, nil
		}
		idxEntrySize := 4 + len(entry.Key) + 8 + 4
		if idxEntrySize == 0 {
			break
		}
		idxPos += uint32(idxEntrySize)
	}

	return nil, false, nil
}

func (sst *SSTable) Get(key []byte) (*Entry, error) {
	// Check bloom filter first
	if !sst.bloomFilter.Contains(key) {
		return nil, nil
	}

	entryIdx, found, err := sst.findIndexForKey(key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	// Read entry from mmap
	offset := entryIdx.Offset
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

	// Verify checksum
	var calc uint32
	if entry.Deleted {
		calc = crc32.ChecksumIEEE(entry.Key)
	} else {
		calc = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
	}
	if calc != entry.checksum {
		return nil, fmt.Errorf("sstable: checksum mismatch for key %x: expected %08x got %08x", key, entry.checksum, calc)
	}

	return entry, nil
}

func (sst *SSTable) Close() error {
	syscall.Munmap(sst.mmap)
	return sst.file.Close()
}

// LoadSSTable opens an existing SSTable file, memory maps it and reconstructs
// index and bloom filter for reads.
func LoadSSTable(path string, crypto *CryptoProvider) (*SSTable, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	mmap, err := syscall.Mmap(int(file.Fd()), 0, int(stat.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		file.Close()
		return nil, err
	}

	var header struct {
		Magic       uint32
		Version     uint32
		EntryCount  uint32
		IndexOffset uint64
		BloomOffset uint64
		BloomSize   uint32
	}

	reader := bytes.NewReader(mmap)
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		syscall.Munmap(mmap)
		file.Close()
		return nil, err
	}

	if header.Magic != MagicNumber || header.Version != Version {
		syscall.Munmap(mmap)
		file.Close()
		return nil, fmt.Errorf("invalid sstable header")
	}

	// Reconstruct bloom filter
	if int(header.BloomOffset+uint64(header.BloomSize)) > len(mmap) {
		syscall.Munmap(mmap)
		file.Close()
		return nil, fmt.Errorf("sstable: bloom region out of range")
	}
	bloomData := mmap[header.BloomOffset : header.BloomOffset+uint64(header.BloomSize)]
	bf := &BloomFilter{}
	if len(bloomData) >= 16 {
		bf.size = binary.LittleEndian.Uint64(bloomData[0:8])
		bf.hash = binary.LittleEndian.Uint64(bloomData[8:16])
		bits := make([]uint64, (bf.size+63)/64)
		for i := range bits {
			bits[i] = binary.LittleEndian.Uint64(bloomData[16+i*8 : 16+(i+1)*8])
		}
		bf.bits = bits
	}

	// Read index (build a sparse on-disk index to avoid holding all keys in memory)
	if int(header.IndexOffset) > len(mmap) {
		syscall.Munmap(mmap)
		file.Close()
		return nil, fmt.Errorf("sstable: index offset out of range")
	}

	// We'll scan the index to gather sample offsets every N entries.
	const sparseStep = 32 // sample every 32 entries (configurable if needed)
	idxDataStart := header.IndexOffset
	idxReader := bytes.NewReader(mmap[idxDataStart:])
	var firstKey []byte
	var lastKey []byte
	var sampleOffsets []uint32
	var entryIdx int
	for i := 0; i < int(header.EntryCount); i++ {
		pos := uint32(idxReader.Size() - int64(idxReader.Len()))
		var keyLen uint32
		if err := binary.Read(idxReader, binary.LittleEndian, &keyLen); err != nil {
			syscall.Munmap(mmap)
			file.Close()
			return nil, err
		}
		key := make([]byte, keyLen)
		if _, err := idxReader.Read(key); err != nil {
			syscall.Munmap(mmap)
			file.Close()
			return nil, err
		}
		var off uint64
		var size uint32
		if err := binary.Read(idxReader, binary.LittleEndian, &off); err != nil {
			syscall.Munmap(mmap)
			file.Close()
			return nil, err
		}
		if err := binary.Read(idxReader, binary.LittleEndian, &size); err != nil {
			syscall.Munmap(mmap)
			file.Close()
			return nil, err
		}

		if entryIdx == 0 {
			firstKey = append([]byte{}, key...)
		}
		lastKey = append([]byte{}, key...)

		if entryIdx%sparseStep == 0 {
			sampleOffsets = append(sampleOffsets, pos)
		}
		entryIdx++
	}

	sst := &SSTable{
		file:               file,
		mmap:               mmap,
		indexOffset:        uint64(idxDataStart),
		entryCount:         int(header.EntryCount),
		indexSampleOffsets: sampleOffsets,
		bloomFilter:        bf,
		crypto:             crypto,
	}

	if entryIdx > 0 {
		sst.minKey = append([]byte{}, firstKey...)
		sst.maxKey = append([]byte{}, lastKey...)
	}

	// For small tables, materialize the full index for faster lookups
	if entryIdx <= 1024 {
		// rewind and read full index into memory
		idxReader = bytes.NewReader(mmap[idxDataStart:])
		var indexEntries []IndexEntry
		for i := 0; i < entryIdx; i++ {
			var keyLen uint32
			binary.Read(idxReader, binary.LittleEndian, &keyLen)
			key := make([]byte, keyLen)
			idxReader.Read(key)
			var off uint64
			var size uint32
			binary.Read(idxReader, binary.LittleEndian, &off)
			binary.Read(idxReader, binary.LittleEndian, &size)
			indexEntries = append(indexEntries, IndexEntry{Key: append([]byte{}, key...), Offset: off, Size: size})
		}
		sst.indexData = indexEntries
	}

	return sst, nil
}

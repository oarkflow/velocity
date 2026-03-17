package velocity

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// RepairSSTable attempts to extract valid entries from a possibly corrupted SSTable
// and writes a repaired SSTable to outPath. It returns the number of entries recovered.
// The strategy: parse entries sequentially from after the header up to bloom offset;
// stop on read/parsing error and write out successfully recovered entries.
func RepairSSTable(inPath, outPath string, crypto *CryptoProvider) (int, error) {
	f, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var header struct {
		Magic       uint32
		Version     uint32
		EntryCount  uint32
		IndexOffset uint64
		BloomOffset uint64
		BloomSize   uint32
	}

	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return 0, fmt.Errorf("failed to read header: %w", err)
	}
	if header.Magic != MagicNumber || header.Version != Version {
		return 0, fmt.Errorf("invalid sstable header")
	}

	// We'll iterate from after header (current offset) until bloom offset.
	startOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	// Determine file size and set sane recovery limit. If bloom offset seems
	// invalid (truncated or corrupted), fall back to the file size to attempt
	// recovery as much as possible.
	stat, err := f.Stat()
	if err != nil {
		return 0, err
	}
	fileSize := stat.Size()
	limit := int64(header.BloomOffset)
	if limit <= startOffset || limit > fileSize {
		limit = fileSize
	}

	// Instead of collecting all recovered entries into memory, stream them out to a temp SSTable file
	// and build the index as we go. This avoids holding the entire dataset in memory.
	tmpDir := filepath.Dir(outPath)
	var tmpFile *os.File
	tmpFile, err = os.CreateTemp(tmpDir, filepath.Base(outPath)+".tmp.*")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Reserve space for the sstable header
	header = struct {
		Magic       uint32
		Version     uint32
		EntryCount  uint32
		IndexOffset uint64
		BloomOffset uint64
		BloomSize   uint32
	}{
		Magic:   MagicNumber,
		Version: Version,
	}
	if err := binary.Write(tmpFile, binary.LittleEndian, header); err != nil {
		tmpFile.Close()
		return 0, err
	}

	var curOff int64
	curOff, err = tmpFile.Seek(0, io.SeekCurrent)
	if err != nil {
		tmpFile.Close()
		return 0, err
	}
	currentOffset := uint64(curOff)

	// Prepare bloom filter using the header's EntryCount if plausible
	bf := NewBloomFilter(int(header.EntryCount), DefaultBloomFilterBits)
	var indexEntries []IndexEntry
	count := 0

	for {
		pos, _ := f.Seek(0, io.SeekCurrent)
		if pos >= limit {
			break
		}

		var keyLen uint32
		if err := binary.Read(f, binary.LittleEndian, &keyLen); err != nil {
			break
		}

		key := make([]byte, keyLen)
		if _, err := io.ReadFull(f, key); err != nil {
			break
		}

		var nonceLen uint16
		if err := binary.Read(f, binary.LittleEndian, &nonceLen); err != nil {
			break
		}
		nonce := make([]byte, nonceLen)
		if _, err := io.ReadFull(f, nonce); err != nil {
			break
		}

		var valueLen uint32
		if err := binary.Read(f, binary.LittleEndian, &valueLen); err != nil {
			break
		}
		ciphertext := make([]byte, valueLen)
		if _, err := io.ReadFull(f, ciphertext); err != nil {
			break
		}

		var timestamp uint64
		if err := binary.Read(f, binary.LittleEndian, &timestamp); err != nil {
			break
		}

		var expiresAt uint64
		if err := binary.Read(f, binary.LittleEndian, &expiresAt); err != nil {
			break
		}

		var deleted uint8
		if err := binary.Read(f, binary.LittleEndian, &deleted); err != nil {
			break
		}

		var checksum uint32
		if err := binary.Read(f, binary.LittleEndian, &checksum); err != nil {
			break
		}

		plaintext, err := crypto.Decrypt(nonce, ciphertext, buildEntryAAD(key, timestamp, expiresAt, deleted == 1))
		if err != nil {
			break
		}

		// Verify checksum
		var calc uint32
		if deleted == 1 {
			calc = crc32.ChecksumIEEE(key)
		} else {
			calc = crc32.ChecksumIEEE(append(key, plaintext...))
		}
		if calc != checksum {
			break
		}

		// Re-encrypt with current crypto provider (in case of rotation) and write entry to tmp file
		nonce2, ciphertext2, err := crypto.Encrypt(plaintext, buildEntryAAD(key, timestamp, expiresAt, deleted == 1))
		if err != nil {
			tmpFile.Close()
			return count, err
		}

		keyLen2 := uint32(len(key))
		valueLen2 := uint32(len(ciphertext2))
		nonceLen2 := uint16(len(nonce2))

		startOffset := currentOffset

		// Write entry
		if err := binary.Write(tmpFile, binary.LittleEndian, keyLen2); err != nil {
			tmpFile.Close()
			return count, err
		}
		if _, err := tmpFile.Write(key); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, nonceLen2); err != nil {
			tmpFile.Close()
			return count, err
		}
		if _, err := tmpFile.Write(nonce2); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, valueLen2); err != nil {
			tmpFile.Close()
			return count, err
		}
		if _, err := tmpFile.Write(ciphertext2); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, timestamp); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, expiresAt); err != nil {
			tmpFile.Close()
			return count, err
		}
		var delByte uint8
		if deleted == 1 {
			delByte = 1
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, delByte); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, checksum); err != nil {
			tmpFile.Close()
			return count, err
		}

		entrySize := 4 + len(key) + 2 + len(nonce2) + 4 + len(ciphertext2) + 8 + 8 + 1 + 4
		currentOffset += uint64(entrySize)

		indexEntries = append(indexEntries, IndexEntry{Key: append([]byte{}, key...), Offset: startOffset, Size: uint32(entrySize)})
		bf.Add(key)
		count++
	}

	if count == 0 {
		tmpFile.Close()
		return 0, fmt.Errorf("no recoverable entries found")
	}

	// Write bloom filter
	bloomOffset := currentOffset
	bloomData := bf.Marshal()
	if _, err := tmpFile.Write(bloomData); err != nil {
		tmpFile.Close()
		return count, err
	}
	currentOffset += uint64(len(bloomData))

	// Write index
	indexOffset := currentOffset
	for _, idxEntry := range indexEntries {
		keyLen := uint32(len(idxEntry.Key))
		if err := binary.Write(tmpFile, binary.LittleEndian, keyLen); err != nil {
			tmpFile.Close()
			return count, err
		}
		if _, err := tmpFile.Write(idxEntry.Key); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, idxEntry.Offset); err != nil {
			tmpFile.Close()
			return count, err
		}
		if err := binary.Write(tmpFile, binary.LittleEndian, idxEntry.Size); err != nil {
			tmpFile.Close()
			return count, err
		}
	}

	// Update header with counts and offsets
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		tmpFile.Close()
		return count, err
	}
	header.EntryCount = uint32(count)
	header.IndexOffset = indexOffset
	header.BloomOffset = bloomOffset
	header.BloomSize = uint32(len(bloomData))
	if err := binary.Write(tmpFile, binary.LittleEndian, header); err != nil {
		tmpFile.Close()
		return count, err
	}

	// Ensure everything is flushed to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return count, err
	}
	if err := tmpFile.Close(); err != nil {
		return count, err
	}

	// Atomically rename into place
	if err := os.Rename(tmpFile.Name(), outPath); err != nil {
		return count, err
	}

	return count, nil
}

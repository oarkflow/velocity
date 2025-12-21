package velocity

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
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

	var recovered []*Entry
	for {
		pos, _ := f.Seek(0, io.SeekCurrent)
		if pos >= limit {
			break
		}

		var keyLen uint32
		if err := binary.Read(f, binary.LittleEndian, &keyLen); err != nil {
			// stop on any read error
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

		var deleted uint8
		if err := binary.Read(f, binary.LittleEndian, &deleted); err != nil {
			break
		}

		var checksum uint32
		if err := binary.Read(f, binary.LittleEndian, &checksum); err != nil {
			break
		}

		// Try to decrypt and verify checksum
		plaintext, err := crypto.Decrypt(nonce, ciphertext, buildEntryAAD(key, timestamp, deleted == 1))
		if err != nil {
			break
		}

		entry := &Entry{
			Key:       append([]byte{}, key...),
			Value:     append([]byte{}, plaintext...),
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
			break
		}

		recovered = append(recovered, entry)
	}

	if len(recovered) == 0 {
		return 0, fmt.Errorf("no recoverable entries found")
	}

	// Write out repaired SSTable
	if _, err := NewSSTable(outPath, recovered, crypto); err != nil {
		return len(recovered), fmt.Errorf("failed to write repaired sstable: %w", err)
	}

	return len(recovered), nil
}

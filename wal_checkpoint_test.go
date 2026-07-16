package velocity

import (
	"hash/crc32"
	"path/filepath"
	"testing"
)

func TestWALTruncatePrefixPreservesPostCheckpointWrites(t *testing.T) {
	wal, err := NewWAL(filepath.Join(t.TempDir(), "wal.log"), newNoopCryptoProvider())
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	first := &Entry{Key: []byte("first"), Value: []byte("one"), Timestamp: 1}
	first.checksum = crc32.Update(crc32.ChecksumIEEE(first.Key), crc32.IEEETable, first.Value)
	if err := wal.Write(first); err != nil {
		t.Fatal(err)
	}
	offset, err := wal.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	second := &Entry{Key: []byte("second"), Value: []byte("two"), Timestamp: 2}
	second.checksum = crc32.Update(crc32.ChecksumIEEE(second.Key), crc32.IEEETable, second.Value)
	if err := wal.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := wal.TruncatePrefix(offset); err != nil {
		t.Fatal(err)
	}

	entries, err := wal.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || string(entries[0].Key) != "second" || string(entries[0].Value) != "two" {
		t.Fatalf("replay = %#v, want only post-checkpoint entry", entries)
	}
}

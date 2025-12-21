package velocity

import (
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestRepairSSTableTruncation(t *testing.T) {
	tmp := t.TempDir()
	inPath := filepath.Join(tmp, "sst_corrupt.db")
	outPath := filepath.Join(tmp, "sst_repaired.db")

	entries := []*Entry{
		{Key: []byte("a"), Value: []byte("1"), Timestamp: 1, Deleted: false},
		{Key: []byte("b"), Value: []byte("2"), Timestamp: 2, Deleted: false},
		{Key: []byte("c"), Value: []byte("3"), Timestamp: 3, Deleted: false},
	}
	for _, e := range entries {
		e.checksum = crc32.ChecksumIEEE(append(e.Key, e.Value...))
	}
	crypto, _ := newCryptoProvider(make([]byte, 32))
	_, err := NewSSTable(inPath, entries, crypto)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the file by truncating its end
	f, err := os.OpenFile(inPath, os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	stat, _ := f.Stat()
	// truncate to remove last 50 bytes (likely corrupt the last entry)
	if stat.Size() > 50 {
		if err := f.Truncate(stat.Size() - 50); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	f.Close()

	count, err := RepairSSTable(inPath, outPath, crypto)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected to recover at least one entry")
	}

	// Load repaired sstable and ensure entries exist
	sst, err := LoadSSTable(outPath, crypto)
	if err != nil {
		t.Fatalf("failed loading repaired sstable: %v", err)
	}
	defer sst.Close()

	// At least first entry should be present
	e, err := sst.Get([]byte("a"))
	if err != nil || e == nil {
		t.Fatalf("expected to find 'a' in repaired sstable: %v", err)
	}
}

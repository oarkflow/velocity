package velocity

import (
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSTableAtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sst_test.db")

	entries := []*Entry{
		{Key: []byte("a"), Value: []byte("1"), Timestamp: 1, Deleted: false, checksum: 0},
		{Key: []byte("b"), Value: []byte("2"), Timestamp: 2, Deleted: false, checksum: 0},
	}
	// Pre-compute checksums as callers normally would
	for _, e := range entries {
		e.checksum = crc32.ChecksumIEEE(append(e.Key, e.Value...))
	}

	crypto, _ := newCryptoProvider(make([]byte, 32))
	sst, err := NewSSTable(path, entries, crypto)
	if err != nil {
		t.Fatal(err)
	}
	defer sst.Close()

	// The final file should exist at path
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected final sstable file at %s, stat error: %v", path, err)
	}

	// No leftover temp files matching pattern
	files, _ := os.ReadDir(tmp)
	for _, f := range files {
		name := f.Name()
		if name != filepath.Base(path) {
			// if other files exist (unlikely) ensure none are our tmp pattern
			if strings.HasPrefix(name, filepath.Base(path)+".tmp.") {
				t.Fatalf("found leftover tmp file: %s", name)
			}
		}
	}

	// Validate we can read back entries
	e, err := sst.Get([]byte("a"))
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if string(e.Value) != "1" {
		t.Fatalf("expected 1 got %s", e.Value)
	}
}

package velocity

import (
	"os"
	"testing"
)

func TestWALTruncateAfterFlush(t *testing.T) {
	path := t.TempDir()
	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Force small memtable to trigger flush
	db.memTableSize = 1

	if err := db.Put([]byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}

	// Call flush directly to synchronously create SSTable and truncate WAL
	if err := db.flushMemTable(); err != nil {
		t.Fatal(err)
	}

	// WAL file should exist but be truncated to zero
	stat, err := os.Stat(db.wal.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() != 0 {
		t.Fatalf("expected WAL file size 0 after truncate, got %d", stat.Size())
	}
}

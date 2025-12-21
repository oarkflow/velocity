package velocity

import (
	"encoding/binary"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBatchWriterChecksumAndWALReplay(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	bw := db.NewBatchWriter(2)
	if err := bw.Put([]byte("k1"), []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := bw.Put([]byte("k2"), []byte("v2")); err != nil {
		t.Fatalf("Put2: %v", err)
	}
	// Flush explicitly
	if err := bw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Ensure memtable contains entries after flush
	entryAfterFlush := db.memTable.Get([]byte("k1"))
	if entryAfterFlush == nil || entryAfterFlush.checksum == 0 {
		t.Fatalf("post-flush memtable missing or checksum zero")
	}

	// Capture WAL path and close DB to flush to disk
	walPath := db.wal.file.Name()
	if err := db.Close(); err != nil {
		t.Fatalf("db close: %v", err)
	}

	// Post-close, stat WAL
	if info, err := os.Stat(walPath); err == nil {
		log.Printf("DEBUG: wal file after close: size=%d", info.Size())
	} else {
		log.Printf("DEBUG: wal file stat error: %v", err)
	}

	// List directory contents
	files, _ := os.ReadDir(dir)
	var sstPath string
	for _, f := range files {
		log.Printf("DEBUG: file in dir: %s", f.Name())
		if strings.HasPrefix(f.Name(), "sst_") {
			sstPath = filepath.Join(dir, f.Name())
		}
	}
	if sstPath != "" {
		sst, err := LoadSSTable(sstPath, db.crypto)
		if err != nil {
			log.Printf("DEBUG: failed to load sst directly: %v", err)
		} else {
			entry, err := sst.Get([]byte("k1"))
			if err != nil {
				log.Printf("DEBUG: sst.Get error: %v", err)
			} else if entry == nil {
				log.Printf("DEBUG: sst.Get returned nil for k1")
			} else {
				log.Printf("DEBUG: sst.Get returned k1 -> %s checksum=%08x", string(entry.Value), entry.checksum)
			}
		}
	}

	// Inspect raw WAL bytes for checksum fields
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	log.Printf("DEBUG: raw wal size: %d bytes", len(raw))
	// naive parse: iterate and extract checksums by scanning entries (debug only)
	var offs int
	var found []uint32
	for offs < len(raw) {
		if offs+4 > len(raw) {
			break
		}
		keyLen := int(binary.LittleEndian.Uint32(raw[offs : offs+4]))
		offs += 4
		if offs+keyLen > len(raw) {
			break
		}
		offs += keyLen
		if offs+2 > len(raw) {
			break
		}
		nonceLen := int(binary.LittleEndian.Uint16(raw[offs : offs+2]))
		offs += 2
		if offs+nonceLen > len(raw) {
			break
		}
		offs += nonceLen
		if offs+4 > len(raw) {
			break
		}
		valLen := int(binary.LittleEndian.Uint32(raw[offs : offs+4]))
		offs += 4
		if offs+valLen > len(raw) {
			break
		}
		offs += valLen
		if offs+8 > len(raw) {
			break
		}
		offs += 8 // timestamp
		if offs+1 > len(raw) {
			break
		}
		offs += 1 // deleted
		if offs+4 > len(raw) {
			break
		}
		ck := binary.LittleEndian.Uint32(raw[offs : offs+4])
		offs += 4
		found = append(found, ck)
	}
	log.Printf("DEBUG: raw WAL checksums: %v", found)
	for _, ck := range found {
		if ck == 0 {
			t.Fatalf("found zero checksum in WAL file (raw parse): %v", found)
		}
	}

	// Reopen DB from same dir and validate replay
	db2, err := New(dir)
	if err != nil {
		t.Fatalf("failed to reopen db: %v", err)
	}
	defer db2.Close()
	log.Printf("DEBUG: db2 sstable count: %d", len(db2.sstables))
	if len(db2.sstables) > 0 {
		ent, err := db2.sstables[0].Get([]byte("k1"))
		if err != nil {
			log.Printf("DEBUG: db2.sstables[0].Get error: %v", err)
		} else if ent == nil {
			log.Printf("DEBUG: db2.sstables[0].Get returned nil for k1")
		} else {
			log.Printf("DEBUG: db2.sstables[0].Get returned k1 -> %s checksum=%08x", string(ent.Value), ent.checksum)
		}
	}

	// Basic read from DB should work after replay
	val, err := db2.Get([]byte("k1"))
	if err != nil {
		log.Printf("DEBUG: db2.Get error: %v", err)
		// try sst directly
		if len(db2.sstables) > 0 {
			ent, _ := db2.sstables[0].Get([]byte("k1"))
			if ent != nil {
				log.Printf("DEBUG: sst direct found k1 -> %s checksum=%08x", string(ent.Value), ent.checksum)
			}
		}
		t.Fatalf("Get k1: %v", err)
	}
	if string(val) != "v1" {
		t.Fatalf("unexpected value k1: %s", string(val))
	}
	// ensure data is present (either in memtable or in SSTable) and checksum non-zero
	entry := db2.memTable.Get([]byte("k1"))
	if entry != nil {
		if entry.checksum == 0 {
			t.Fatalf("entry checksum zero after replay in memtable")
		}
	} else {
		// check SSTable
		if len(db2.sstables) == 0 {
			t.Fatalf("no sstables found and memtable missing entry after replay")
		}
		ent, err := db2.sstables[0].Get([]byte("k1"))
		if err != nil {
			t.Fatalf("sst.Get error: %v", err)
		}
		if ent == nil || ent.checksum == 0 {
			t.Fatalf("sst entry missing or checksum zero after replay")
		}
	}
}

func TestWALWriteAndReplay(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New db: %v", err)
	}
	defer db.Close()

	// Direct WAL write with checksum set
	entry := &Entry{Key: []byte("wx"), Value: []byte("vy"), Timestamp: uint64(12345), Deleted: false}
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
	if err := db.wal.Write(entry); err != nil {
		t.Fatalf("wal write: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("db close: %v", err)
	}

	// Reopen and verify replay
	db2, err := New(dir)
	if err != nil {
		t.Fatalf("failed to reopen db: %v", err)
	}
	defer db2.Close()

	val, err := db2.Get([]byte("wx"))
	if err != nil {
		t.Fatalf("Get wx: %v", err)
	}
	if string(val) != "vy" {
		t.Fatalf("unexpected value wx: %s", string(val))
	}
	ent := db2.memTable.Get([]byte("wx"))
	if ent == nil || ent.checksum == 0 {
		t.Fatalf("entry missing or checksum zero after replay")
	}
}

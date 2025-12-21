package velocity

import (
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWALRotateAndRetention(t *testing.T) {
	path := t.TempDir()
	walPath := filepath.Join(path, "wal.log")
	crypto, _ := newCryptoProvider(make([]byte, 32))
	w, err := NewWAL(walPath, crypto)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// enable rotation at tiny size
	w.SetRotationPolicy(1, "", 2, 0)

	// Write a couple entries to ensure file grows
	entry := &Entry{Key: []byte("k"), Value: []byte("v"), Timestamp: 1, checksum: 0}
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
	if err := w.Write(entry); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(entry); err != nil {
		t.Fatal(err)
	}

	// Force a rotation now
	if err := w.RotateNow(); err != nil {
		t.Fatal(err)
	}

	// Archive dir should exist
	archive := filepath.Join(filepath.Dir(walPath), "wal_archive")
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("expected archive dir, stat error: %v", err)
	}

	// There should be at least one rotated file
	files, _ := os.ReadDir(archive)
	found := false
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "wal_") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rotated wal file in archive")
	}

	// New WAL should exist and be writable
	if _, err := w.file.Stat(); err != nil {
		t.Fatalf("stat new wal failed: %v", err)
	}

	// Archive stats should report at least one file
	count, total, names, err := w.ArchiveStats()
	if err != nil {
		t.Fatalf("ArchiveStats error: %v", err)
	}
	if count < 1 || total == 0 || len(names) == 0 {
		t.Fatalf("unexpected archive stats: count=%d total=%d files=%v", count, total, names)
	}
}

func TestRotationByInterval(t *testing.T) {
	path := t.TempDir()
	walPath := filepath.Join(path, "wal.log")
	crypto, _ := newCryptoProvider(make([]byte, 32))
	w, err := NewWAL(walPath, crypto)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Set a rotation interval and make lastRotationTime sufficiently old
	w.SetRotationInterval(2 * time.Second)
	w.SetRotationPolicy(0, "", 0, 0)

	// write an entry so rotated wal contains data
	entry := &Entry{Key: []byte("k2"), Value: []byte("v2"), Timestamp: 1, checksum: 0}
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
	if err := w.Write(entry); err != nil {
		t.Fatal(err)
	}

	w.mutex.Lock()
	w.lastRotationTime = time.Now().Add(-5 * time.Second)
	w.mutex.Unlock()

	// Trigger rotation check synchronously
	if err := w.CheckRotation(); err != nil {
		t.Fatalf("CheckRotation failed: %v", err)
	}

	// Archive dir should exist
	archive := filepath.Join(filepath.Dir(walPath), "wal_archive")
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("expected archive dir after interval rotation, stat error: %v", err)
	}

	count, total, names, err := w.ArchiveStats()
	if err != nil {
		t.Fatalf("ArchiveStats error: %v", err)
	}
	if count < 1 || total == 0 || len(names) == 0 {
		t.Fatalf("unexpected archive stats after interval rotation: count=%d total=%d files=%v", count, total, names)
	}
}

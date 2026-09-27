package productiontest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

// findWALFile locates the WAL file storage-lsm writes under dir (named
// "wal.log" — see plugins/storage-lsm/engine.go's walFileName constant).
func findWALFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "wal.log")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected WAL file at %s: %v", path, err)
	}
	return path
}

// corruptByteAt flips one byte at the given offset (or the last byte if
// offset is beyond the file) directly on disk, bypassing the plugin API
// entirely — simulating real on-disk bit-rot / a torn write, not an
// API-level failure.
func corruptByteAt(t *testing.T, path string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if offset >= info.Size() {
		offset = info.Size() - 1
	}
	if offset < 0 {
		t.Fatalf("file %s is empty, nothing to corrupt", path)
	}
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, offset); err != nil {
		t.Fatal(err)
	}
	buf[0] ^= 0xFF
	if _, err := f.WriteAt(buf, offset); err != nil {
		t.Fatal(err)
	}
}

// TestCorruptionRejection_WALBitFlipNeverReturnsWrongData writes real
// data, bit-flips the on-disk WAL file at several offsets (beginning,
// middle, end), and verifies that reopening never silently returns
// corrupted data as if it were valid: either the corrupted record (and
// only records after it, per the documented torn-write-tail tolerance)
// is dropped, or the engine fails to open outright — both are acceptable,
// silently-wrong data is not.
func TestCorruptionRejection_WALBitFlipNeverReturnsWrongData(t *testing.T) {
	ctx := context.Background()

	writeSample := func(dir string) (keys []string, values [][]byte) {
		eng, err := storagelsm.Open(dir, true)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			key := []byte("k" + string(rune('a'+i)))
			val := []byte("value-payload-" + string(rune('a'+i)))
			if err := eng.Put(ctx, api.Entry{Key: key, Value: val}); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, string(key))
			values = append(values, val)
		}
		// Deliberately do NOT call eng.Close(): a clean Close flushes
		// everything to an SSTable and truncates the WAL to empty (proven
		// by inspection), which would leave nothing in wal.log to
		// corrupt. always_sync=true already fsynced every record above,
		// so the data is durably in wal.log without a clean shutdown —
		// this simulates a crash before any checkpoint, which is exactly
		// the WAL-replay path this test targets.
		return keys, values
	}

	offsets := []int64{0, 1, 50, -1} // -1 means "near the end", resolved by corruptByteAt

	for _, off := range offsets {
		t.Run("offset", func(t *testing.T) {
			dir := t.TempDir()
			keys, values := writeSample(dir)
			walPath := findWALFile(t, dir)

			target := off
			if target < 0 {
				info, err := os.Stat(walPath)
				if err != nil {
					t.Fatal(err)
				}
				target = info.Size() - 3
			}
			corruptByteAt(t, walPath, target)

			eng, err := storagelsm.Open(dir, true)
			if err != nil {
				// Failing to open outright on unrecoverable corruption is
				// an acceptable, safe outcome — it never returns wrong
				// data because it returns none.
				t.Logf("offset=%d: Open failed loudly on corruption (acceptable): %v", target, err)
				return
			}
			defer eng.Close()

			// Whatever subset of records the engine recovered, every one
			// it DOES return must have the value that was actually
			// written for that key — never a mismatched/garbage value.
			recovered := 0
			for i, k := range keys {
				val, found, err := eng.Get(ctx, []byte(k))
				if err != nil {
					t.Fatalf("offset=%d: Get(%s) returned an error instead of clean not-found/found: %v", target, k, err)
				}
				if !found {
					continue
				}
				recovered++
				if string(val) != string(values[i]) {
					t.Fatalf("offset=%d: key %s returned WRONG data %q (want %q or not-found) — silent corruption, the one unacceptable outcome",
						target, k, val, values[i])
				}
			}
			t.Logf("offset=%d: engine opened after corruption, %d/%d records recovered, zero silently-wrong values", target, recovered, len(keys))
		})
	}
}

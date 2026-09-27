package lsm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// TestFlushTriggeredByThreshold proves a small memtable size threshold
// actually causes an automatic flush to a real on-disk SSTable file, not
// just an internal counter bump.
func TestFlushTriggeredByThreshold(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// A tiny threshold so a handful of small puts is guaranteed to cross it.
	e, err := Open(dir, true, WithFlushThreshold(64), WithCompactionThreshold(100))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for i := 0; i < 20; i++ {
		if err := e.Put(ctx, api.Entry{Key: []byte(fmt.Sprintf("key-%03d", i)), Value: []byte("some-value-bytes")}); err != nil {
			t.Fatal(err)
		}
	}

	if e.FlushCount() == 0 {
		t.Fatal("expected at least one automatic flush once the memtable threshold was exceeded")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "sstable-*.sst"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one sstable-*.sst file on disk after a flush")
	}
}

// TestGetAfterFlushStillWorks proves a key that has left the memtable
// (flushed into an SSTable) is still found correctly.
func TestGetAfterFlushStillWorks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true, WithFlushThreshold(1<<30), WithCompactionThreshold(100))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Put(ctx, api.Entry{Key: []byte("flushed-key"), Value: []byte("flushed-value")}); err != nil {
		t.Fatal(err)
	}
	if err := e.Checkpoint(ctx); err != nil { // forces an immediate flush regardless of size threshold
		t.Fatal(err)
	}
	if len(e.memtable) != 0 {
		t.Fatal("expected memtable to be empty immediately after a flush")
	}

	v, ok, err := e.Get(ctx, []byte("flushed-key"))
	if err != nil || !ok || string(v) != "flushed-value" {
		t.Fatalf("expected flushed key to still be readable via the sstable path, got %q %v %v", v, ok, err)
	}
}

// TestCompactionMergesAndDropsShadowedTombstones proves compaction
// correctly merges two overlapping SSTables, keeps only the newest value
// per key, and drops a tombstone once nothing below it needs shadowing.
func TestCompactionMergesAndDropsShadowedTombstones(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true, WithFlushThreshold(1<<30), WithCompactionThreshold(2))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// First sstable: "a" and "b".
	must(t, e.Put(ctx, api.Entry{Key: []byte("a"), Value: []byte("a-old")}))
	must(t, e.Put(ctx, api.Entry{Key: []byte("b"), Value: []byte("b-stays")}))
	must(t, e.Checkpoint(ctx))

	// Second sstable: overwrite "a", delete "b" — pushes sstable count to 2
	// (== compactionThreshold), triggering a compaction on this flush.
	must(t, e.Put(ctx, api.Entry{Key: []byte("a"), Value: []byte("a-new")}))
	must(t, e.Delete(ctx, []byte("b")))
	must(t, e.Checkpoint(ctx))

	if e.CompactionCount() == 0 {
		t.Fatal("expected compaction to have run once the sstable count reached the threshold")
	}
	if got := e.SSTableCount(); got != 1 {
		t.Fatalf("expected exactly 1 sstable after a full-merge compaction, got %d", got)
	}

	v, ok, err := e.Get(ctx, []byte("a"))
	if err != nil || !ok || string(v) != "a-new" {
		t.Fatalf("expected the newer value to survive compaction, got %q %v %v", v, ok, err)
	}
	_, ok, err = e.Get(ctx, []byte("b"))
	if err != nil || ok {
		t.Fatalf("expected deleted key to stay deleted after compaction, got ok=%v err=%v", ok, err)
	}

	// The merged sstable's own index should no longer contain a tombstone
	// for "b" at all — it was safe to drop since nothing remains below it.
	merged := e.sstables[0]
	if ie, present := merged.index["b"]; present && ie.kind == recDelete {
		t.Fatal("expected the tombstone for \"b\" to be dropped by compaction, not merely re-written")
	}
}

// TestBloomFilterAvoidsUnnecessarySSTableReads proves the Bloom filter
// actually short-circuits a lookup for a key that provably isn't in a
// given sstable, rather than the engine falling back to a full read.
func TestBloomFilterAvoidsUnnecessarySSTableReads(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true, WithFlushThreshold(1<<30), WithCompactionThreshold(100))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for i := 0; i < 50; i++ {
		must(t, e.Put(ctx, api.Entry{Key: []byte(fmt.Sprintf("present-%03d", i)), Value: []byte("v")}))
	}
	must(t, e.Checkpoint(ctx)) // flush all 50 into one sstable

	before := e.BloomSkipCount()
	// A key that was never written should, with overwhelming probability
	// for a 1%-false-positive-rate filter over 50 items, be caught by the
	// Bloom filter rather than requiring an index/data lookup.
	if _, ok, err := e.Get(ctx, []byte("definitely-absent-key-xyz")); err != nil || ok {
		t.Fatalf("expected absent key to be reported not-found, got ok=%v err=%v", ok, err)
	}
	after := e.BloomSkipCount()
	if after <= before {
		t.Fatalf("expected BloomSkipCount to increase for a definitely-absent key, before=%d after=%d", before, after)
	}
}

// TestCrashDuringFlushRecoversFromWALAlone simulates a crash that occurs
// after a flush's temp SSTable file was written but BEFORE it was renamed
// into place (and therefore before the WAL was truncated). Reopening must
// ignore the stray .tmp file and recover everything from the still-intact
// WAL.
func TestCrashDuringFlushRecoversFromWALAlone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	e, err := Open(dir, true, WithFlushThreshold(1<<30), WithCompactionThreshold(100))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		must(t, e.Put(ctx, api.Entry{Key: []byte(fmt.Sprintf("k%d", i)), Value: []byte("v")}))
	}

	// Simulate the exact interrupted-flush window: a temp sstable file
	// exists on disk (as if buildSSTable had just finished writing it),
	// but the rename-into-place and WAL-truncate that would normally
	// follow immediately never happened, because the "process" is about
	// to "crash" right here.
	tmpPath := sstableFileName(dir, 999) + ".tmp"
	if err := os.WriteFile(tmpPath, []byte("partial-garbage-from-an-interrupted-flush"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.w.f.Close() // simulate the crash: no clean Close(), no final flush

	e2, err := Open(dir, true)
	if err != nil {
		t.Fatalf("expected Open to tolerate a stray .tmp file from an interrupted flush, got: %v", err)
	}
	defer e2.Close()

	if got := e2.SSTableCount(); got != 0 {
		t.Fatalf("expected the stray .tmp file to be ignored (0 real sstables loaded), got %d", got)
	}
	for i := 0; i < 10; i++ {
		v, ok, err := e2.Get(ctx, []byte(fmt.Sprintf("k%d", i)))
		if err != nil || !ok || string(v) != "v" {
			t.Fatalf("key k%d not recovered from WAL after simulated crash-during-flush: ok=%v err=%v", i, ok, err)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

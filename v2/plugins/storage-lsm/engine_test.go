package lsm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestPutGetDelete(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Put(ctx, api.Entry{Key: []byte("a"), Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	v, ok, err := e.Get(ctx, []byte("a"))
	if err != nil || !ok || string(v) != "1" {
		t.Fatalf("got %q %v %v", v, ok, err)
	}

	if err := e.Delete(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	_, ok, _ = e.Get(ctx, []byte("a"))
	if ok {
		t.Fatal("expected key deleted")
	}
}

func TestWALReplayAfterReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := e.Put(ctx, api.Entry{Key: []byte(keyN(i)), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	// No Close()/Checkpoint(): simulate a crash — reopening must replay the
	// WAL and recover every write.
	e.w.f.Close()

	e2, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	for i := 0; i < 100; i++ {
		_, ok, err := e2.Get(ctx, []byte(keyN(i)))
		if err != nil || !ok {
			t.Fatalf("key %d not recovered: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestCheckpointTruncatesWALAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Put(ctx, api.Entry{Key: []byte("k"), Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, walFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected WAL truncated to empty after checkpoint, got size %d", info.Size())
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	e2, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	v, ok, err := e2.Get(ctx, []byte("k"))
	if err != nil || !ok || string(v) != "v" {
		t.Fatalf("expected key recovered from snapshot after checkpoint, got %q %v %v", v, ok, err)
	}
}

func TestTornWriteTailIsIgnoredOnReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Put(ctx, api.Entry{Key: []byte("good"), Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	e.w.f.Close()

	// Simulate a torn write: append a few garbage bytes to the WAL tail,
	// mimicking a crash mid-append of the next record.
	f, err := os.OpenFile(filepath.Join(dir, walFileName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	e2, err := Open(dir, true)
	if err != nil {
		t.Fatalf("expected replay to tolerate torn tail, got error: %v", err)
	}
	defer e2.Close()
	v, ok, err := e2.Get(ctx, []byte("good"))
	if err != nil || !ok || string(v) != "v" {
		t.Fatalf("expected well-formed record before the torn tail to survive, got %q %v %v", v, ok, err)
	}
}

func TestTTLExpiry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Put(ctx, api.Entry{Key: []byte("temp"), Value: []byte("v"), TTL: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	_, ok, err := e.Get(ctx, []byte("temp"))
	if err != nil || ok {
		t.Fatalf("expected expired key to be absent, got ok=%v err=%v", ok, err)
	}
}

func TestBatchAtomicApply(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	ops := []api.BatchOp{
		{Entry: api.Entry{Key: []byte("b1"), Value: []byte("1")}},
		{Entry: api.Entry{Key: []byte("b2"), Value: []byte("2")}},
	}
	if err := e.Batch(ctx, ops); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"b1", "b2"} {
		if _, ok, _ := e.Get(ctx, []byte(k)); !ok {
			t.Fatalf("expected %s present after batch", k)
		}
	}
}

func TestScanPrefixAndSnapshotIsolation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for _, k := range []string{"user:1", "user:2", "order:1"} {
		if err := e.Put(ctx, api.Entry{Key: []byte(k), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}

	it, err := e.Scan(ctx, []byte("user:"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for it.Next() {
		got = append(got, string(it.Key()))
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 user: keys, got %v", got)
	}

	snap, err := e.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Release()

	if err := e.Delete(ctx, []byte("user:1")); err != nil {
		t.Fatal(err)
	}
	// Snapshot was taken before the delete: it must still see the old value.
	if _, ok, _ := snap.Get([]byte("user:1")); !ok {
		t.Fatal("expected snapshot to retain pre-delete view")
	}
	if _, ok, _ := e.Get(ctx, []byte("user:1")); ok {
		t.Fatal("expected live engine to reflect the delete")
	}
}

func keyN(i int) string {
	return "key-" + string(rune('a'+i%26)) + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

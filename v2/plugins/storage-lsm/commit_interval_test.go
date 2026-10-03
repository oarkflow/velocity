package lsm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// TestCommitInterval_PumpSyncsInBackground proves the bounded-staleness
// contract: writes staged with alwaysSync=false (Put returns WITHOUT
// waiting for durability) still become durable within about one
// commitInterval of being staged, with NO caller ever asking for a sync —
// the background commit pump does it, coalescing every write staged in
// the window into one fsync.
func TestCommitInterval_PumpSyncsInBackground(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, false,
		WithFsyncMode(FsyncPosix),
		WithCommitInterval(5*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	const n = 200
	for i := 0; i < n; i++ {
		if err := e.Put(ctx, api.Entry{
			Key:   []byte(fmt.Sprintf("k%04d", i)),
			Value: []byte(fmt.Sprintf("v%04d", i)),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Wait for the pump (bounded-staleness deadline + generous scheduling
	// slack) — nobody has called Sync or waited for durability.
	deadline := time.Now().Add(2 * time.Second)
	for e.SyncCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("commit pump never fsynced within deadline (syncCount=0 after %d staged writes)", n)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// One observed fsync may have covered only a prefix (a tick can fire
	// mid-staging); give the pump several more intervals so a full tick
	// after staging completed has certainly run.
	time.Sleep(50 * time.Millisecond)

	// Durability proof WITHOUT a clean Close (Close flushes the memtable
	// and would mask the WAL-pump behavior): reopen the same directory
	// while the first engine is still open and idle — WAL replay must see
	// every staged write the pump has committed.
	e2, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	for i := 0; i < n; i++ {
		v, ok, err := e2.Get(ctx, []byte(fmt.Sprintf("k%04d", i)))
		if err != nil || !ok || string(v) != fmt.Sprintf("v%04d", i) {
			t.Fatalf("k%04d after pump commit: got %q, %v, %v; want value, true, nil", i, v, ok, err)
		}
	}

	syncs := e.SyncCount()
	if syncs >= n {
		t.Fatalf("expected the pump to coalesce fsyncs (%d writes -> < %d fsyncs), got syncCount=%d", n, n, syncs)
	}
	t.Logf("%d staged writes covered by %d background fsyncs (~%d writes/fsync)", n, syncs, n/max64(syncs, 1))
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCommitInterval_SyncBarrier proves Engine.Sync is a real durability
// barrier for commit-coalescing callers: after Sync returns, every write
// staged before it survives a reopen, regardless of the pump.
func TestCommitInterval_SyncBarrier(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, false,
		WithFsyncMode(FsyncPosix),
		WithCommitInterval(time.Hour), // effectively no pump help during the test
	)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 50; i++ {
		if err := e.Put(ctx, api.Entry{Key: []byte(fmt.Sprintf("k%d", i)), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	// Reopen while the first engine is still open: only the Sync barrier
	// makes these durable (the pump interval is an hour away).
	e2, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	for i := 0; i < 50; i++ {
		if _, ok, err := e2.Get(ctx, []byte(fmt.Sprintf("k%d", i))); err != nil || !ok {
			t.Fatalf("k%d not durable after Sync: ok=%v err=%v", i, ok, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCommitInterval_PumpDoesNotFsyncWhenIdle proves an idle engine with
// a commit pump armed does not perform fsync syscalls at all — sync() is
// a no-op at the syscall level when nothing has been staged since the
// last durable generation, so a tiny interval does not become a periodic
// disk tax on read-only workloads.
func TestCommitInterval_PumpDoesNotFsyncWhenIdle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, false,
		WithFsyncMode(FsyncPosix),
		WithCommitInterval(2*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Put(ctx, api.Entry{Key: []byte("k"), Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	// Wait for the one outstanding write to be committed.
	deadline := time.Now().Add(2 * time.Second)
	for e.SyncCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("pump never committed the outstanding write")
		}
		time.Sleep(2 * time.Millisecond)
	}
	base := e.SyncCount()
	time.Sleep(50 * time.Millisecond) // ~25 idle pump ticks
	if got := e.SyncCount(); got != base {
		t.Fatalf("idle pump performed %d extra fsyncs (syncCount %d -> %d); it must not fsync when nothing is staged", got-base, base, got)
	}
}

// TestNoCommitInterval_NoBackgroundSync proves the default (commit
// interval unset) is unchanged: staged writes with alwaysSync=false are
// NOT fsynced in the background; durability comes only from an explicit
// sync, a flush/checkpoint, or Close.
func TestNoCommitInterval_NoBackgroundSync(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, false, WithFsyncMode(FsyncPosix))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for i := 0; i < 100; i++ {
		if err := e.Put(ctx, api.Entry{Key: []byte(fmt.Sprintf("k%d", i)), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if got := e.SyncCount(); got != 0 {
		t.Fatalf("expected no background fsyncs without commit_interval, got %d", got)
	}
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.SyncCount(); got == 0 {
		t.Fatal("explicit Sync must perform an fsync when writes are outstanding")
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

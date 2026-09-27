package lsm

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// TestGroupCommit_ConcurrentPutsCoalesceFsyncs is the actual proof group
// commit works: N concurrent, durable Puts must all succeed and be
// correctly recorded, but the number of REAL fsync syscalls performed
// must be meaningfully less than N — one fsync durably committing many
// writers is the whole point (see wal.go's waitForSync doc).
func TestGroupCommit_ConcurrentPutsCoalesceFsyncs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true) // alwaysSync: true — every Put must be durable before it returns
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = e.Put(ctx, api.Entry{
				Key:   []byte(fmt.Sprintf("k%d", i)),
				Value: []byte(fmt.Sprintf("v%d", i)),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		v, ok, err := e.Get(ctx, []byte(fmt.Sprintf("k%d", i)))
		wantV := fmt.Sprintf("v%d", i)
		if err != nil || !ok || string(v) != wantV {
			t.Fatalf("key k%d: got %q, %v, %v; want %q, true, nil", i, v, ok, err, wantV)
		}
	}

	syncs := e.SyncCount()
	t.Logf("%d concurrent durable Puts completed with %d real fsync syscalls (%.1fx coalescing)", n, syncs, float64(n)/float64(syncs))
	if syncs >= n {
		t.Fatalf("expected group commit to coalesce fsyncs (syncCount < %d writes), got syncCount=%d — no coalescing occurred", n, syncs)
	}
	// A conservative bound: real fsync latency plus goroutine scheduling
	// should coalesce this many concurrent writers into well under half as
	// many syscalls on any reasonable machine. This is deliberately loose
	// to avoid flakiness on slow/loaded CI runners while still proving
	// meaningful coalescing, not just "one fewer than n".
	if syncs > n/2 {
		t.Fatalf("expected substantial fsync coalescing (syncCount <= %d), got syncCount=%d — group commit may not be batching effectively", n/2, syncs)
	}
}

// TestGroupCommit_AcknowledgedWritesSurviveCrash proves the durability
// invariant group commit must never weaken: once a Put has returned
// successfully (meaning waitForSync confirmed its generation was
// fsynced), that write must survive even a hard crash immediately
// afterward — regardless of how many OTHER concurrent writers were
// coalesced into the same fsync round.
func TestGroupCommit_AcknowledgedWritesSurviveCrash(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = e.Put(ctx, api.Entry{
				Key:   []byte(fmt.Sprintf("k%d", i)),
				Value: []byte(fmt.Sprintf("v%d", i)),
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	// Simulate a hard crash: close the raw file descriptor directly,
	// bypassing wal.close()'s own flush/sync — exactly the same technique
	// TestCrashDuringFlushRecoversFromWALAlone uses. Every Put above
	// already returned successfully, so every one of them must have been
	// durably fsynced BEFORE this point, group commit or not.
	e.w.f.Close()

	e2, err := Open(dir, true)
	if err != nil {
		t.Fatalf("reopen after simulated crash: %v", err)
	}
	defer e2.Close()

	for i := 0; i < n; i++ {
		v, ok, err := e2.Get(ctx, []byte(fmt.Sprintf("k%d", i)))
		wantV := fmt.Sprintf("v%d", i)
		if err != nil || !ok || string(v) != wantV {
			t.Fatalf("key k%d not recovered after simulated crash (acknowledged write must survive): got %q, %v, %v; want %q, true, nil", i, v, ok, err, wantV)
		}
	}
}

package lsm

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// TestGetInto_MatchesGet is the correctness contract for the buffer-reusing
// read: byte-identical results to Get across memtable-resident data, flushed
// data, shadowed keys, tombstones and misses.
func TestGetInto_MatchesGet(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true, WithFlushThreshold(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	putAll(t, e, "a", "b", "c", "d")
	// force a flush so later reads take the sstable path
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	// shadow two of them from the memtable (newer must win)
	putAll(t, e, "b", "d")
	// and delete one that lives in the table
	if err := e.Delete(ctx, []byte("c")); err != nil {
		t.Fatal(err)
	}
	// an already-expired entry
	if err := e.Put(ctx, api.Entry{Key: []byte("e"), Value: []byte("gone"), TTL: 20 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	for _, k := range []string{"a", "b", "c", "d", "e", "absent"} {
		want, wantOK, wantErr := e.Get(ctx, []byte(k))
		got, gotOK, gotErr := e.GetInto(ctx, k, nil)
		if (wantErr != nil) != (gotErr != nil) {
			t.Fatalf("%q: Get err=%v, GetInto err=%v", k, wantErr, gotErr)
		}
		if wantOK != gotOK {
			t.Fatalf("%q: Get ok=%v, GetInto ok=%v", k, wantOK, gotOK)
		}
		if wantOK && string(got) != string(want) {
			t.Fatalf("%q: Get=%q, GetInto=%q", k, want, got)
		}
	}
}

// TestGetInto_ReusedBufferNeverLeaksStaleBytes guards the aliasing contract:
// after a long value then a short one into the same buffer, the short result
// must be exactly the short value.
func TestGetInto_ReusedBufferNeverLeaksStaleBytes(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	putAll(t, e, "long", "short")
	// a value long enough to force the buffer to grow past its initial cap
	if err := e.Put(ctx, api.Entry{Key: []byte("long"), Value: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}); err != nil {
		t.Fatal(err)
	}
	if err := e.Put(ctx, api.Entry{Key: []byte("short"), Value: []byte("bb")}); err != nil {
		t.Fatal(err)
	}
	// force one of them to the sstable path so both are exercised
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 0, 4)
	out, hit, err := e.GetInto(ctx, "long", buf)
	if err != nil || !hit || string(out) != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("long: out=%q hit=%v err=%v", out, hit, err)
	}
	out, hit, err = e.GetInto(ctx, "short", out)
	if err != nil || !hit || string(out) != "bb" {
		t.Fatalf("short: out=%q (len %d) hit=%v err=%v — stale bytes leaked", out, len(out), hit, err)
	}
}

// TestGetInto_DoesNotAllocateWhenBufferReused is the reason the method exists.
func TestGetInto_DoesNotAllocateWhenBufferReused(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	putAll(t, e, "k1", "k2", "k3")
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}

	keys := []string{"k1", "k2", "k3"}
	buf := make([]byte, 0, 128)
	// warm up
	for _, k := range keys {
		if _, _, err := e.GetInto(ctx, k, buf); err != nil {
			t.Fatal(err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		for _, k := range keys {
			if _, _, err := e.GetInto(ctx, k, buf); err != nil {
				t.Fatal(err)
			}
		}
	})
	// Values here are tiny (putAll writes "v-<key>"), so the sstable read stays
	// inside the 512-byte speculative window and writes straight into buf: a
	// reused buffer must therefore cost ZERO allocations. The per-record header
	// arrays are caller-owned and the speculative read buffer is pooled, so
	// nothing else may allocate either. (A value larger than 512 bytes needs a
	// second, right-sized read buffer — bounded, and not what this covers.)
	//
	// Skipped under -race: the race runtime's own allocations are counted by
	// AllocsPerRun, and sync.Pool's reuse interacts with it, so an exact-zero
	// assertion is not meaningful in a race build.
	if raceEnabled {
		t.Skip("exact allocation counts are unreliable under -race")
	}
	if allocs != 0 {
		t.Fatalf("GetInto allocated %.0f times over 1500 small reads; expected 0", allocs)
	}
}

// TestGetString_MatchesGet covers the string-keyed fast path.
func TestGetString_MatchesGet(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true, WithFlushThreshold(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	putAll(t, e, "x", "y")
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	putAll(t, e, "x")

	for _, k := range []string{"x", "y", "zzz", ""} {
		want, wantOK, _ := e.Get(ctx, []byte(k))
		got, gotOK, _ := e.GetString(ctx, k)
		if wantOK != gotOK {
			t.Fatalf("%q: Get ok=%v, GetString ok=%v", k, wantOK, gotOK)
		}
		if wantOK && string(got) != string(want) {
			t.Fatalf("%q: Get=%q, GetString=%q", k, want, got)
		}
	}
}

// TestGetInto_ResultIsIndependentOfEngineState: the caller must own its buffer,
// so mutating it cannot corrupt the store.
func TestGetInto_ResultIsIndependentOfEngineState(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Put(ctx, api.Entry{Key: []byte("k"), Value: []byte("original")}); err != nil {
		t.Fatal(err)
	}
	out, _, err := e.GetInto(ctx, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range out {
		out[i] = 'X'
	}
	again, _, err := e.GetInto(ctx, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "original" {
		t.Fatalf("mutating the returned buffer corrupted the store: %q", again)
	}
}

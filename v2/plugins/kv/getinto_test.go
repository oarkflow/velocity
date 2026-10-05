package kv

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// asBufferKV asserts the optional capability and returns it.
func asBufferKV(t *testing.T, p *Plugin) api.BufferKVService {
	t.Helper()
	bks, ok := any(p).(api.BufferKVService)
	if !ok {
		t.Fatal("kv.Plugin must implement api.BufferKVService")
	}
	return bks
}

// layerBackend is a test-only api.StorageBackend that models a two-layer
// engine: a mutable "memtable" and a flushed "table" that shadows it, so the
// GetInto tests can exercise the shadowing precedence that a real LSM engine
// has and a flat map cannot.
type layerBackend struct {
	mu     sync.RWMutex
	mem    map[string][]byte
	table  map[string][]byte
	tombst map[string]bool
}

func newLayerBackend() *layerBackend {
	return &layerBackend{
		mem:    map[string][]byte{},
		table:  map[string][]byte{},
		tombst: map[string]bool{},
	}
}

func (b *layerBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	k := string(key)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.tombst[k] {
		return nil, false, nil
	}
	if v, ok := b.mem[k]; ok {
		out := make([]byte, len(v))
		copy(out, v)
		return out, true, nil
	}
	v, ok := b.table[k]
	if !ok {
		return nil, false, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, true, nil
}

// GetString + GetInto make this backend exercise kv's fast paths.
func (b *layerBackend) GetString(ctx context.Context, key string) ([]byte, bool, error) {
	return b.Get(ctx, []byte(key))
}

func (b *layerBackend) GetInto(ctx context.Context, key string, dst []byte) ([]byte, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.tombst[key] {
		return dst, false, nil
	}
	v, ok := b.mem[key]
	if !ok {
		v, ok = b.table[key]
	}
	if !ok {
		return dst, false, nil
	}
	return append(dst[:0], v...), true, nil
}

func (b *layerBackend) Put(ctx context.Context, e api.Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(e.Value))
	copy(cp, e.Value)
	b.mem[string(e.Key)] = cp
	delete(b.tombst, string(e.Key))
	return nil
}

func (b *layerBackend) Delete(ctx context.Context, key []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := string(key)
	delete(b.mem, k)
	delete(b.table, k)
	b.tombst[k] = true
	return nil
}

func (b *layerBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	for _, op := range ops {
		if op.Delete {
			_ = b.Delete(ctx, op.Entry.Key)
			continue
		}
		_ = b.Put(ctx, op.Entry)
	}
	return nil
}

func (b *layerBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var keys []string
	for k := range b.mem {
		if len(k) >= len(prefix) && k[:len(prefix)] == string(prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = b.mem[k]
	}
	return &layerIter{keys: keys, vals: vals, pos: -1}, nil
}

func (b *layerBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	return nil, fmt.Errorf("not needed for these tests")
}

func (b *layerBackend) Close() error { return nil }

// flush moves the memtable into the table layer, so later reads take the
// "disk" path.
func (b *layerBackend) flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.mem {
		b.table[k] = v
	}
	b.mem = map[string][]byte{}
}

type layerIter struct {
	keys []string
	vals [][]byte
	pos  int
}

func (i *layerIter) Next() bool    { i.pos++; return i.pos < len(i.keys) }
func (i *layerIter) Key() []byte   { return []byte(i.keys[i.pos]) }
func (i *layerIter) Value() []byte { return i.vals[i.pos] }
func (i *layerIter) Err() error    { return nil }
func (i *layerIter) Close() error  { return nil }

// TestGetInto_MatchesGet is the correctness contract: the buffer-reusing read
// must be byte-identical to Get, across memtable-resident data, flushed data,
// shadowed keys, tombstones, and misses.
func TestGetInto_MatchesGet(t *testing.T) {
	ctx := context.Background()
	b := newLayerBackend()
	p := &Plugin{storage: b}
	bks := asBufferKV(t, p)

	for i := 0; i < 30; i++ {
		if err := p.Put(ctx, fmt.Sprintf("k%02d", i), []byte(fmt.Sprintf("v%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// flush half, then overwrite some of them so both layers hold the key
	b.flush()
	for i := 0; i < 30; i += 2 {
		if err := p.Put(ctx, fmt.Sprintf("k%02d", i), []byte(fmt.Sprintf("NEW%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// a deleted key that also exists in the table
	if err := p.Delete(ctx, "k05"); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{
		"k00", "k01", "k04", "k05", "k29", "absent", "zzz", "k", "k1",
	} {
		want, wantOK, wantErr := p.Get(ctx, k)
		got, _, gotOK, gotErr := getInto(t, bks, k, nil)
		if (wantErr != nil) != (gotErr != nil) {
			t.Fatalf("%q: Get err=%v but GetInto err=%v", k, wantErr, gotErr)
		}
		if wantOK != gotOK {
			t.Fatalf("%q: Get ok=%v, GetInto ok=%v", k, wantOK, gotOK)
		}
		if wantOK && string(got) != string(want) {
			t.Fatalf("%q: Get=%q, GetInto=%q", k, want, got)
		}
	}
}

// TestGetInto_RejectsEmptyKeyLikeGet: the fast path must not become a way to
// bypass validation.
func TestGetInto_RejectsEmptyKeyLikeGet(t *testing.T) {
	p := &Plugin{storage: newLayerBackend()}
	bks := asBufferKV(t, p)
	if _, _, err := p.Get(context.Background(), ""); err == nil {
		t.Fatal("expected Get to reject empty key")
	}
	if _, _, err := bks.GetInto(context.Background(), "", nil); err == nil {
		t.Fatal("GetInto must reject empty key just like Get")
	}
}

// TestGetInto_ReusedBufferNeverLeaksStaleBytes is the aliasing contract: after
// reading a long value then a short one into the same buffer, the short result
// must be exactly the short value.
func TestGetInto_ReusedBufferNeverLeaksStaleBytes(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newLayerBackend()}
	bks := asBufferKV(t, p)
	if err := p.Put(ctx, "long", []byte("aaaaaaaaaaaaaaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if err := p.Put(ctx, "short", []byte("bb")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 0, 4)
	out, _, hit, err := getInto(t, bks, "long", buf)
	if err != nil || !hit || string(out) != "aaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("long: out=%q hit=%v err=%v", out, hit, err)
	}
	// Reuse the SAME backing memory for a much shorter value.
	out, _, hit, err = getInto(t, bks, "short", out)
	if err != nil || !hit || string(out) != "bb" {
		t.Fatalf("short: out=%q (len %d) hit=%v err=%v — stale bytes leaked", out, len(out), hit, err)
	}
	// A miss must report not-found. The returned buffer is intentionally left
	// untouched on a miss (a caller that ignores hit would otherwise read a
	// stale value), so the meaningful assertion is hit==false — not the
	// buffer's contents.
	_, _, hit, err = getInto(t, bks, "missing", out)
	if err != nil || hit {
		t.Fatalf("miss: hit=%v err=%v", hit, err)
	}
}

// TestGetInto_DoesNotAllocateWhenBufferReused is the reason the method exists.
func TestGetInto_DoesNotAllocateWhenBufferReused(t *testing.T) {
	ctx := context.Background()
	b := newLayerBackend()
	p := &Plugin{storage: b}
	bks := asBufferKV(t, p)

	keys := make([]string, 20)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d", i)
		if err := p.Put(ctx, keys[i], []byte("0123456789abcdef")); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 0, 64)
	// warm up
	for _, k := range keys {
		if _, _, _, err := getInto(t, bks, k, buf); err != nil {
			t.Fatal(err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		for _, k := range keys {
			if _, _, _, err := getInto(t, bks, k, buf); err != nil {
				t.Fatal(err)
			}
		}
	})
	// Zero: the keys are pre-built and the buffer is reused, so GetInto must
	// not allocate at all. One allocation would mean the fast path is not
	// being taken.
	if raceEnabledKV {
		t.Skip("exact allocation counts are unreliable under -race")
	}
	if allocs != 0 {
		t.Fatalf("GetInto allocated %.0f times over 10000 reads; expected 0", allocs)
	}
}

// TestGetInto_ResultIsIndependentOfEngineState: the caller must own its buffer,
// so mutating it cannot corrupt the store.
func TestGetInto_ResultIsIndependentOfEngineState(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newLayerBackend()}
	bks := asBufferKV(t, p)
	if err := p.Put(ctx, "k", []byte("original")); err != nil {
		t.Fatal(err)
	}
	out, _, _, err := getInto(t, bks, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range out {
		out[i] = 'X'
	}
	again, _, _, err := getInto(t, bks, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "original" {
		t.Fatalf("mutating the returned buffer corrupted the store: %q", again)
	}
}

// TestGetInto_FallsBackForPlainBackend: a backend with neither optional
// capability must still work, returning the same values.
func TestGetInto_FallsBackForPlainBackend(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()} // memBackend implements neither
	bks := asBufferKV(t, p)
	if err := p.Put(ctx, "k", []byte("val")); err != nil {
		t.Fatal(err)
	}
	got, _, hit, err := getInto(t, bks, "k", nil)
	if err != nil || !hit || string(got) != "val" {
		t.Fatalf("fallback: out=%q hit=%v err=%v", got, hit, err)
	}
	want, ok, err := p.Get(ctx, "k")
	if err != nil || !ok || string(want) != "val" {
		t.Fatalf("Get disagrees with fallback: %q %v %v", want, ok, err)
	}
}

func getInto(t *testing.T, bks api.BufferKVService, key string, buf []byte) ([]byte, []byte, bool, error) {
	t.Helper()
	out, hit, err := bks.GetInto(context.Background(), key, buf)
	return out, buf, hit, err
}

package redisdata

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// --- minimal in-memory StorageBackend stub, kept local to this test so it
// doesn't depend on the storage-mem plugin package. Mirrors the pattern
// already used by plugins/secret's test suite. ---

type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}

func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}

func (m *memBackend) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = op.Entry.Value
		}
	}
	return nil
}

func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, string(prefix)) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &memIterator{backend: m, keys: keys, idx: -1}, nil
}

func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string][]byte, len(m.data))
	for k, v := range m.data {
		cp[k] = v
	}
	return &memSnapshot{data: cp}, nil
}

func (m *memBackend) Close() error { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool {
	it.idx++
	return it.idx < len(it.keys)
}

func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }

func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}

func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

type memSnapshot struct{ data map[string][]byte }

func (s *memSnapshot) Get(key []byte) ([]byte, bool, error) {
	v, ok := s.data[string(key)]
	return v, ok, nil
}
func (s *memSnapshot) Release() {}

func newTestPlugin() *Plugin {
	p := NewPlugin("storage-lsm")
	p.storage = newMemBackend()
	return p
}

func bs(strs ...string) [][]byte {
	out := make([][]byte, len(strs))
	for i, s := range strs {
		out[i] = []byte(s)
	}
	return out
}

func assertByteSlices(t *testing.T, got [][]byte, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range got {
		if string(got[i]) != want[i] {
			t.Fatalf("index %d: got %q, want %q (full got=%q want=%q)", i, got[i], want[i], got, want)
		}
	}
}

func TestList_PushPopOrderAndLen(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if n, err := p.RPush(ctx, "l", []byte("a"), []byte("b")); err != nil || n != 2 {
		t.Fatalf("RPush: n=%d err=%v", n, err)
	}
	if n, err := p.LPush(ctx, "l", []byte("z"), []byte("y")); err != nil || n != 4 {
		t.Fatalf("LPush: n=%d err=%v", n, err)
	}
	// LPUSH l z y -> y is pushed after z, so y ends up as the new head:
	// order should be [y z a b].
	if n, err := p.LLen(ctx, "l"); err != nil || n != 4 {
		t.Fatalf("LLen: n=%d err=%v", n, err)
	}
	got, err := p.LRange(ctx, "l", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "y", "z", "a", "b")

	v, ok, err := p.LPop(ctx, "l")
	if err != nil || !ok || string(v) != "y" {
		t.Fatalf("LPop: v=%q ok=%v err=%v", v, ok, err)
	}
	v, ok, err = p.RPop(ctx, "l")
	if err != nil || !ok || string(v) != "b" {
		t.Fatalf("RPop: v=%q ok=%v err=%v", v, ok, err)
	}
	if n, err := p.LLen(ctx, "l"); err != nil || n != 2 {
		t.Fatalf("LLen after pops: n=%d err=%v", n, err)
	}

	// Drain and confirm empty behaves cleanly.
	p.LPop(ctx, "l")
	p.LPop(ctx, "l")
	if _, ok, err := p.LPop(ctx, "l"); err != nil || ok {
		t.Fatalf("LPop on empty: ok=%v err=%v", ok, err)
	}
	if n, err := p.LLen(ctx, "l"); err != nil || n != 0 {
		t.Fatalf("LLen on empty: n=%d err=%v", n, err)
	}
}

func TestList_LRangeNegativeIndices(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	p.RPush(ctx, "l", bs("a", "b", "c", "d", "e")...)

	got, err := p.LRange(ctx, "l", -3, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "c", "d", "e")

	got, err = p.LRange(ctx, "l", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "a", "b", "c", "d", "e")

	got, err = p.LRange(ctx, "l", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("out-of-range LRange: got %q, want empty", got)
	}
}

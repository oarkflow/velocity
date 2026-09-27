package object

import (
	"bytes"
	"context"
	"sort"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// memBackend is a minimal, test-only api.StorageBackend. It intentionally
// does not depend on plugins/storage-mem (built in parallel by another
// agent) so this package's tests are self-contained.
type memBackend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true, nil
}

func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := make([]byte, len(e.Value))
	copy(v, e.Value)
	m.data[string(e.Key)] = v
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
			continue
		}
		v := make([]byte, len(op.Entry.Value))
		copy(v, op.Entry.Value)
		m.data[string(op.Entry.Key)] = v
	}
	return nil
}

type memIterator struct {
	keys []string
	vals [][]byte
	idx  int
}

func (it *memIterator) Next() bool    { it.idx++; return it.idx < len(it.keys) }
func (it *memIterator) Key() []byte   { return []byte(it.keys[it.idx]) }
func (it *memIterator) Value() []byte { return it.vals[it.idx] }
func (it *memIterator) Err() error    { return nil }
func (it *memIterator) Close() error  { return nil }

func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = m.data[k]
	}
	return &memIterator{keys: keys, vals: vals, idx: -1}, nil
}

type memSnapshot struct{ b *memBackend }

func (s *memSnapshot) Get(key []byte) ([]byte, bool, error) {
	return s.b.Get(context.Background(), key)
}
func (s *memSnapshot) Release() {}

func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	return &memSnapshot{b: m}, nil
}

func (m *memBackend) Close() error { return nil }

var _ api.StorageBackend = (*memBackend)(nil)

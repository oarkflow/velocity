package backup

import (
	"bytes"
	"context"
	"sort"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// memStore is a minimal in-test api.StorageBackend, so these tests don't
// depend on any other plugin's package.
type memStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: make(map[string][]byte)} }

func (m *memStore) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}

func (m *memStore) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = append([]byte(nil), e.Value...)
	return nil
}

func (m *memStore) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *memStore) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = append([]byte(nil), op.Entry.Value...)
		}
	}
	return nil
}

func (m *memStore) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &memIterator{store: m, keys: keys, idx: -1}, nil
}

func (m *memStore) Snapshot(ctx context.Context) (api.Snapshot, error) { return nil, nil }
func (m *memStore) Close() error                                       { return nil }

type memIterator struct {
	store *memStore
	keys  []string
	idx   int
}

func (it *memIterator) Next() bool {
	it.idx++
	return it.idx < len(it.keys)
}

func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }
func (it *memIterator) Value() []byte {
	it.store.mu.RLock()
	defer it.store.mu.RUnlock()
	return it.store.data[it.keys[it.idx]]
}
func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

var _ api.StorageBackend = (*memStore)(nil)

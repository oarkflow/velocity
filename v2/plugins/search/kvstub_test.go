package search

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memKV is a minimal in-memory api.KVService stub used only by this
// package's tests, so search's tests are not blocked on any other
// plugin's package existing or compiling.
type memKV struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemKV() *memKV {
	return &memKV{data: make(map[string][]byte)}
}

func (m *memKV) Put(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *memKV) PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return m.Put(ctx, key, value)
}

func (m *memKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	return v, ok, nil
}

func (m *memKV) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memKV) Exists(ctx context.Context, key string) (bool, error) {
	_, ok, _ := m.Get(ctx, key)
	return ok, nil
}

func (m *memKV) Incr(ctx context.Context, key string, delta int64) (int64, error) {
	return 0, nil
}

func (m *memKV) Keys(ctx context.Context, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for k := range m.data {
		out = append(out, k)
	}
	return out, nil
}

func (m *memKV) Scan(ctx context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	start := 0
	if cursor != "" {
		for i, k := range keys {
			if k > cursor {
				start = i
				break
			}
			start = i + 1
		}
	}

	out := make(map[string][]byte)
	next := ""
	end := start
	for end < len(keys) && (limit <= 0 || len(out) < limit) {
		out[keys[end]] = m.data[keys[end]]
		end++
	}
	if end < len(keys) {
		next = keys[end-1]
	}
	return out, next, nil
}

var _ api.KVService = (*memKV)(nil)

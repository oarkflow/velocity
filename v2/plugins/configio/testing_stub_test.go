package configio

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memKV is a minimal, real, correctly-paginating api.KVService stub for
// tests — no dependency on the real kv plugin (a leaf package this one
// doesn't need to pull in just to test against).
type memKV struct {
	data map[string][]byte
}

func newMemKV() *memKV { return &memKV{data: map[string][]byte{}} }

func (m *memKV) Put(ctx context.Context, key string, value []byte) error {
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *memKV) PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return m.Put(ctx, key, value)
}

func (m *memKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, ok := m.data[key]
	return v, ok, nil
}

func (m *memKV) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *memKV) Exists(ctx context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *memKV) Incr(ctx context.Context, key string, delta int64) (int64, error) {
	return 0, nil
}

func (m *memKV) Keys(ctx context.Context, pattern string) ([]string, error) {
	var out []string
	for k := range m.data {
		out = append(out, k)
	}
	return out, nil
}

// Scan implements real pagination semantics matching api/kv.go's
// documented contract: cursor names the NEXT key to return (not the last
// one already returned), sorted-key order for determinism, nextCursor
// empty when exhausted.
func (m *memKV) Scan(ctx context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
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
			if k == cursor {
				start = i
				break
			}
		}
	}

	items := make(map[string][]byte)
	nextCursor := ""
	count := 0
	for i := start; i < len(keys); i++ {
		if limit > 0 && count >= limit {
			nextCursor = keys[i]
			break
		}
		items[keys[i]] = m.data[keys[i]]
		count++
	}
	return items, nextCursor, nil
}

var _ api.KVService = (*memKV)(nil)

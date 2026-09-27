package sql

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memKV is a minimal, dependency-free api.KVService implementation used
// only by this package's tests, so they don't have to block on the
// separately-developed plugins/kv package. It is not exported and not
// used by the plugin itself.
type memKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemKV() *memKV { return &memKV{data: map[string][]byte{}} }

func (m *memKV) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *memKV) PutWithTTL(ctx context.Context, key string, value []byte, _ time.Duration) error {
	return m.Put(ctx, key, value)
}

func (m *memKV) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true, nil
}

func (m *memKV) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memKV) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *memKV) Incr(_ context.Context, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cur int64
	if v, ok := m.data[key]; ok {
		for _, c := range v {
			cur = cur*10 + int64(c-'0')
		}
	}
	cur += delta
	m.data[key] = []byte(itoa(cur))
	return cur, nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (m *memKV) Keys(_ context.Context, pattern string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.data {
		if pattern == "" || pattern == "*" || strings.Contains(k, strings.Trim(pattern, "*")) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memKV) Scan(_ context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	items := map[string][]byte{}
	next := ""
	end := start
	for end < len(keys) && (limit <= 0 || len(items) < limit) {
		items[keys[end]] = m.data[keys[end]]
		end++
	}
	if end < len(keys) {
		next = keys[end-1]
	}
	return items, next, nil
}

var _ api.KVService = (*memKV)(nil)

// Package mem implements a pure in-memory api.StorageBackend: no WAL, no
// disk I/O, no durability across process restarts. Intended for tests and
// for embedding Velocity v2 where durability is handled by the host
// application itself.
package mem

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

type entryValue struct {
	value     []byte
	expiresAt int64
}

// Engine is the concrete in-memory api.StorageBackend.
type Engine struct {
	mu    sync.RWMutex
	index map[string]entryValue
}

// NewEngine constructs an empty in-memory engine.
func NewEngine() *Engine {
	return &Engine{index: make(map[string]entryValue)}
}

func nowExpiry(ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	return time.Now().Add(ttl).UnixNano()
}

func isExpired(expiresAt int64) bool {
	return expiresAt != 0 && time.Now().UnixNano() >= expiresAt
}

func (e *Engine) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getLocked(string(key))
}

// GetString implements api.StringKeyedGetter: Get without the
// string->[]byte->string round trip the generic path is forced to make.
func (e *Engine) GetString(ctx context.Context, key string) ([]byte, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getLocked(key)
}

// GetInto implements api.BufferGetter, decoding into the caller's buffer so a
// repeated-read loop reuses one allocation instead of one per lookup.
func (e *Engine) GetInto(ctx context.Context, key string, dst []byte) ([]byte, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	v, ok := e.index[key]
	if !ok || isExpired(v.expiresAt) {
		return dst, false, nil
	}
	return append(dst[:0], v.value...), true, nil
}

func (e *Engine) getLocked(key string) ([]byte, bool, error) {
	v, ok := e.index[key]
	if !ok || isExpired(v.expiresAt) {
		return nil, false, nil
	}
	out := make([]byte, len(v.value))
	copy(out, v.value)
	return out, true, nil
}

func (e *Engine) Put(ctx context.Context, ent api.Entry) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	val := make([]byte, len(ent.Value))
	copy(val, ent.Value)
	e.index[string(ent.Key)] = entryValue{value: val, expiresAt: nowExpiry(ent.TTL)}
	return nil
}

func (e *Engine) Delete(ctx context.Context, key []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.index, string(key))
	return nil
}

func (e *Engine) Batch(ctx context.Context, ops []api.BatchOp) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(e.index, string(op.Entry.Key))
			continue
		}
		val := make([]byte, len(op.Entry.Value))
		copy(val, op.Entry.Value)
		e.index[string(op.Entry.Key)] = entryValue{value: val, expiresAt: nowExpiry(op.Entry.TTL)}
	}
	return nil
}

func (e *Engine) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	return e.scanFrom(ctx, prefix, nil, 0)
}

// ScanFrom implements api.RangedScanner, so a paginated caller resumes at
// startKey instead of re-collecting every key under the prefix on each page.
func (e *Engine) ScanFrom(ctx context.Context, prefix, startKey []byte, maxKeys int) (api.Iterator, error) {
	return e.scanFrom(ctx, prefix, startKey, maxKeys)
}

func (e *Engine) scanFrom(ctx context.Context, prefix, startKey []byte, maxKeys int) (api.Iterator, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p := string(prefix)
	var lo string
	if len(startKey) > 0 {
		lo = string(startKey)
	}
	var keys []string
	for k, v := range e.index {
		if len(k) >= len(p) && k[:len(p)] == p && (lo == "" || k >= lo) && !isExpired(v.expiresAt) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	// Truncate only AFTER sorting: map iteration order is random, so cutting
	// the collection short would yield an arbitrary subset of the prefix and
	// silently drop keys that later pages are supposed to return.
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	values := make([][]byte, len(keys))
	for i, k := range keys {
		values[i] = e.index[k].value
	}
	return &sliceIterator{keys: keys, values: values, pos: -1}, nil
}

type sliceIterator struct {
	keys   []string
	values [][]byte
	pos    int
}

func (it *sliceIterator) Next() bool {
	it.pos++
	return it.pos < len(it.keys)
}
func (it *sliceIterator) Key() []byte   { return []byte(it.keys[it.pos]) }
func (it *sliceIterator) Value() []byte { return it.values[it.pos] }
func (it *sliceIterator) Err() error    { return nil }
func (it *sliceIterator) Close() error  { return nil }

// snapshot is a shallow copy-on-read view: a deep copy of the index map
// taken at Snapshot() time, so later writes to the live engine don't
// affect it.
type snapshot struct {
	data map[string]entryValue
}

func (s *snapshot) Get(key []byte) ([]byte, bool, error) {
	v, ok := s.data[string(key)]
	if !ok || isExpired(v.expiresAt) {
		return nil, false, nil
	}
	return v.value, true, nil
}
func (s *snapshot) Release() {}

func (e *Engine) Snapshot(ctx context.Context) (api.Snapshot, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make(map[string]entryValue, len(e.index))
	for k, v := range e.index {
		cp[k] = v
	}
	return &snapshot{data: cp}, nil
}

func (e *Engine) Close() error { return nil }

var _ api.StorageBackend = (*Engine)(nil)

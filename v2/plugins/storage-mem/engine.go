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
	v, ok := e.index[string(key)]
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
	e.mu.RLock()
	defer e.mu.RUnlock()
	p := string(prefix)
	var keys []string
	for k, v := range e.index {
		if len(k) >= len(p) && k[:len(p)] == p && !isExpired(v.expiresAt) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
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

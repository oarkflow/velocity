package sqldriver

import (
	"context"
	"sort"
	"sync"
	"time"
)

type rowLockManager struct {
	mu    sync.Mutex
	locks map[string]*rowLock
	pool  sync.Pool
}

type rowLock struct {
	mu   sync.Mutex
	refs int
}

func newRowLockManager() *rowLockManager {
	return &rowLockManager{
		locks: make(map[string]*rowLock),
		pool: sync.Pool{New: func() any {
			return &rowLock{}
		}},
	}
}

func (m *rowLockManager) acquire(ctx context.Context, keys []string) (func(), error) {
	if len(keys) == 0 {
		return func() {}, nil
	}
	if len(keys) == 1 {
		key := keys[0]
		if key == "" {
			return func() {}, nil
		}
		l, err := m.acquireOne(ctx, key)
		if err != nil {
			return nil, err
		}
		return func() {
			l.mu.Unlock()
			m.mu.Lock()
			if held := m.locks[key]; held != nil {
				held.refs--
				if held.refs == 0 {
					delete(m.locks, key)
					m.pool.Put(held)
				}
			}
			m.mu.Unlock()
		}, nil
	}
	ordered := make([]string, 0, len(keys))
	unique := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		ordered = append(ordered, key)
	}
	return m.acquireUnique(ctx, ordered)
}

func (m *rowLockManager) acquireUnique(ctx context.Context, ordered []string) (func(), error) {
	if len(ordered) == 0 {
		return func() {}, nil
	}
	if len(ordered) == 1 {
		return m.acquire(ctx, ordered)
	}
	sort.Strings(ordered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	acquired := make([]*rowLock, 0, len(ordered))
	for _, key := range ordered {
		l, err := m.acquireOne(ctx, key)
		if err != nil {
			for i := len(acquired) - 1; i >= 0; i-- {
				acquired[i].mu.Unlock()
			}
			m.mu.Lock()
			for _, acquiredKey := range ordered[:len(acquired)] {
				if held := m.locks[acquiredKey]; held != nil {
					held.refs--
					if held.refs == 0 {
						delete(m.locks, acquiredKey)
						m.pool.Put(held)
					}
				}
			}
			m.mu.Unlock()
			return nil, err
		}
		acquired = append(acquired, l)
	}

	return func() {
		for i := len(acquired) - 1; i >= 0; i-- {
			acquired[i].mu.Unlock()
		}
		m.mu.Lock()
		for _, key := range ordered {
			if l := m.locks[key]; l != nil {
				l.refs--
				if l.refs == 0 {
					delete(m.locks, key)
					m.pool.Put(l)
				}
			}
		}
		m.mu.Unlock()
	}, nil
}

func (m *rowLockManager) acquireOne(ctx context.Context, key string) (*rowLock, error) {
	m.mu.Lock()
	l := m.locks[key]
	if l == nil {
		l = m.pool.Get().(*rowLock)
		l.refs = 0
		m.locks[key] = l
	}
	l.refs++
	m.mu.Unlock()

	for !l.mu.TryLock() {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			l.refs--
			if l.refs == 0 {
				delete(m.locks, key)
				m.pool.Put(l)
			}
			m.mu.Unlock()
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return l, nil
}

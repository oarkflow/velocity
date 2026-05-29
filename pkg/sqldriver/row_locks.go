package sqldriver

import (
	"context"
	"sort"
	"sync"
)

type rowLockManager struct {
	mu    sync.Mutex
	locks map[string]*rowLock
}

type rowLock struct {
	mu   sync.Mutex
	refs int
}

func newRowLockManager() *rowLockManager {
	return &rowLockManager{locks: make(map[string]*rowLock)}
}

func (m *rowLockManager) acquire(ctx context.Context, keys []string) (func(), error) {
	if len(keys) == 0 {
		return func() {}, nil
	}
	unique := make(map[string]struct{}, len(keys))
	ordered := make([]string, 0, len(keys))
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
	sort.Strings(ordered)
	if len(ordered) == 0 {
		return func() {}, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	acquired := make([]*rowLock, 0, len(ordered))
	for _, key := range ordered {
		m.mu.Lock()
		l := m.locks[key]
		if l == nil {
			l = &rowLock{}
			m.locks[key] = l
		}
		l.refs++
		m.mu.Unlock()

		l.mu.Lock()
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
				}
			}
		}
		m.mu.Unlock()
	}, nil
}

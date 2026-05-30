package kg

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type testStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newTestStore() *testStore {
	return &testStore{data: make(map[string][]byte)}
}

func (s *testStore) Get(key []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.data[string(key)]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return append([]byte(nil), value...), nil
}

func (s *testStore) Put(key, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[string(key)] = append([]byte(nil), value...)
	return nil
}

func (s *testStore) Delete(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, string(key))
	return nil
}

func (s *testStore) Keys(pattern string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for key := range s.data {
		if ok, _ := filepath.Match(pattern, key); ok || strings.TrimSuffix(pattern, "*") == pattern || strings.HasPrefix(key, strings.TrimSuffix(pattern, "*")) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *testStore) PutIndexedText(key, value []byte) error { return s.Put(key, value) }
func (s *testStore) DeleteIndexed(key []byte) error         { return s.Delete(key) }
func (s *testStore) RegisterChunkSearchPrefix(string)       {}

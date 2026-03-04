package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/storage"
)

const usageCollection = "authz_usage"

type usageRecord struct {
	Count       int   `json:"count"`
	WindowStart int64 `json:"window_start"`
}

// MemoryUsageCounter is the default in-process limiter.
type MemoryUsageCounter struct {
	mu     sync.Mutex
	record map[string]usageRecord
}

func NewMemoryUsageCounter() *MemoryUsageCounter {
	return &MemoryUsageCounter{record: make(map[string]usageRecord)}
}

func (m *MemoryUsageCounter) Consume(ctx context.Context, scope string, subjectType licclient.SubjectType, subjectID string, amount int, windowSeconds int, limit int) error {
	_ = ctx
	if limit <= 0 {
		return nil
	}
	if amount <= 0 {
		amount = 1
	}
	key := usageKey(scope, subjectType, subjectID)
	now := time.Now().Unix()

	m.mu.Lock()
	defer m.mu.Unlock()

	rec := m.record[key]
	if rec.WindowStart == 0 {
		rec.WindowStart = now
	}
	if windowSeconds > 0 && now-rec.WindowStart >= int64(windowSeconds) {
		rec.Count = 0
		rec.WindowStart = now
	}
	if rec.Count+amount > limit {
		return fmt.Errorf("entitlement limit exceeded for scope: %s", scope)
	}
	rec.Count += amount
	m.record[key] = rec
	return nil
}

// StoreUsageCounter persists counters in encrypted Secretr storage.
type StoreUsageCounter struct {
	store *storage.Store
	mu    sync.Mutex
}

func NewStoreUsageCounter(store *storage.Store) *StoreUsageCounter {
	if store == nil {
		return nil
	}
	return &StoreUsageCounter{store: store}
}

func (s *StoreUsageCounter) Consume(ctx context.Context, scope string, subjectType licclient.SubjectType, subjectID string, amount int, windowSeconds int, limit int) error {
	if s == nil || s.store == nil || limit <= 0 {
		return nil
	}
	if amount <= 0 {
		amount = 1
	}
	key := usageKey(scope, subjectType, subjectID)
	now := time.Now().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	var rec usageRecord
	b, err := s.store.Get(ctx, usageCollection, key)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		rec.WindowStart = now
	} else if len(b) > 0 {
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
	}

	if rec.WindowStart == 0 {
		rec.WindowStart = now
	}
	if windowSeconds > 0 && now-rec.WindowStart >= int64(windowSeconds) {
		rec.Count = 0
		rec.WindowStart = now
	}
	if rec.Count+amount > limit {
		return fmt.Errorf("entitlement limit exceeded for scope: %s", scope)
	}
	rec.Count += amount
	enc, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.store.Set(ctx, usageCollection, key, enc)
}

func usageKey(scope string, subjectType licclient.SubjectType, subjectID string) string {
	if subjectID == "" {
		subjectID = "unknown"
	}
	return fmt.Sprintf("%s:%s:%s", scope, subjectType, subjectID)
}

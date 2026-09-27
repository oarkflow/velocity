package api

import (
	"context"
	"time"
)

// KVService is the key-value surface plugins/kv exposes, built on top of a
// StorageBackend looked up from the registry. It publishes TopicKVPut /
// TopicKVDelete on every mutation so observer plugins (compliance,
// replication, notifications) can react without kv importing them.
type KVService interface {
	Put(ctx context.Context, key string, value []byte) error
	PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Incr(ctx context.Context, key string, delta int64) (int64, error)
	// Keys returns all keys matching a glob pattern. Intended for small
	// keyspaces / tooling — Scan is the paginated, production-safe path.
	Keys(ctx context.Context, pattern string) ([]string, error)
	// Scan returns up to limit items with the given prefix, resuming from
	// cursor (empty string starts at the beginning). nextCursor is empty
	// when there are no more items.
	Scan(ctx context.Context, prefix string, limit int, cursor string) (items map[string][]byte, nextCursor string, err error)
}

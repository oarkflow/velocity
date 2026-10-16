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

// KVKeysIter is an OPTIONAL capability of a KVService (query via type
// assertion, like KVStreamScanner): the keys-only half of StreamScanner
// delivered as the storage iterator's native []byte rather than a
// converted string, and optionally starting at a seek key.
//
// Why both exist: index lookups whose payload lives in the KEY (the SQL
// engine's range index) examine every key under a prefix but retain only
// the subset that satisfies the query range — today every walked key costs
// one string conversion allocation, ~5k-10k per query on a 10k-entry
// bucket. The []byte variant lets such a caller decode straight from the
// iterator's transient bytes and convert only retained keys. The seek
// variant (ScanKeysIterFrom) lets a range query with a lower bound skip
// the prefix of the bucket below the bound entirely.
//
// fn receives the key bytes in ascending order. The slice is transient:
// it is valid only until the next fn call or the scan's end, so callers
// must copy (e.g. string(k)) if they retain anything past the callback.
// Returning false from fn stops the walk cleanly.
type KVKeysIter interface {
	// ScanKeysIter walks every key under prefix in ascending order.
	ScanKeysIter(ctx context.Context, prefix string, fn func(key []byte) (bool, error)) error
	// ScanKeysIterFrom behaves identically to ScanKeysIter, except entries
	// whose key sorts strictly BEFORE startKey are skipped. When startKey
	// is empty it is exactly ScanKeysIter. Backends without a seek
	// primitive degrade to scanning from the beginning and skipping, so a
	// caller can safely use the two methods as one coherent contract.
	ScanKeysIterFrom(ctx context.Context, prefix, startKey string, fn func(key []byte) (bool, error)) error
}

// BufferKVService is an optional capability of a KVService (query via type
// assertion, like KVStreamScanner): a Get that decodes into a caller-owned
// buffer.
//
// It is optional, and deliberately a separate interface, so that adding it does
// not break every existing api.KVService implementation. Get necessarily
// allocates one value-sized slice per call — the engine must not hand out
// memory it will later overwrite — and on a hot point-lookup path that
// allocation is the dominant remaining cost after the key conversions are gone.
// A caller that reads in a loop should use GetInto and reuse one buffer.
//
// Only the returned slice's bytes up to its length are valid; bytes past that
// may hold remnants of a previous, longer value. plugins/kv's *Plugin
// implements it.
type BufferKVService interface {
	GetInto(ctx context.Context, key string, buf []byte) ([]byte, bool, error)
}

// KVStreamScanner is an optional capability of a KVService (query via
// type assertion, like Watchable): it walks a prefix as a STREAM,
// invoking fn once per entry in key order, instead of materializing pages
// into a map like Scan. Scan-heavy consumers (the SQL engine's full-table
// and index scans) use it so a 10,000-row walk costs one callback per row
// rather than map buckets, key strings, and value copies per page.
//
// fn receives a key string and the plaintext value (unsealed exactly as
// Get/Scan would return it) and returns (keepGoing, error); returning
// false stops the walk with no error. The value slice must be copied if
// retained past the callback.
//
// ScanKeysStream is the keys-only variant: values are never fetched or
// unsealed at all (the storage iterator never touches them), which is
// what index lookups — whose entries carry their payload in the key —
// should use.
type KVStreamScanner interface {
	ScanStream(ctx context.Context, prefix string, fn func(key string, value []byte) (bool, error)) error
	ScanKeysStream(ctx context.Context, prefix string, fn func(key string) (bool, error)) error
}

package api

import (
	"context"
	"time"
)

// Entry is a single durable record at the StorageBackend level: raw key,
// raw value, optional TTL. Higher-level services (KV, Object, Secret)
// encode their own structure into Key/Value; StorageBackend itself is
// agnostic to what the bytes mean.
type Entry struct {
	Key   []byte
	Value []byte
	TTL   time.Duration // 0 means no expiry
}

// BatchOp is one operation inside a StorageBackend.Batch call.
type BatchOp struct {
	Delete bool
	Entry  Entry // Entry.Value and TTL are ignored when Delete is true
}

// Iterator walks a key range in ascending key order.
type Iterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Err() error
	Close() error
}

// Snapshot is a point-in-time read view. Implementations that don't
// support true MVCC snapshots (e.g. storage-mem) may implement this as a
// copy-on-read view instead — callers should not assume more isolation
// than the backend documents.
type Snapshot interface {
	Get(key []byte) ([]byte, bool, error)
	Release()
}

// StorageBackend is the raw byte-oriented durability engine underneath
// KV, Object, and Secret services. It is the one plugin category every
// other data-plane plugin depends on (via Registry.Lookup("storage")).
// Reference implementations:
//   - plugins/storage-lsm: WAL + memtable + SSTable engine, ported from
//     v1's wal.go/memtable.go/sstable.go/erasure_coding.go/bitrot.go.
//   - plugins/storage-mem: in-memory backend for tests and embedding.
//
// Because KV/Object/Secret depend only on this interface, a new backend
// (e.g. a remote/distributed one) can be added without touching them.
type StorageBackend interface {
	Get(ctx context.Context, key []byte) ([]byte, bool, error)
	Put(ctx context.Context, e Entry) error
	Delete(ctx context.Context, key []byte) error
	Batch(ctx context.Context, ops []BatchOp) error
	// Scan returns an Iterator over all keys with the given prefix.
	Scan(ctx context.Context, prefix []byte) (Iterator, error)
	Snapshot(ctx context.Context) (Snapshot, error)
	Close() error
}

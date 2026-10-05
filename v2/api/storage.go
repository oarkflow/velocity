package api

import (
	"context"
	"errors"
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
// Iterator walks a key range in ascending key order.
//
// Key and Value return slices that are only guaranteed valid until the
// next call to Next (implementations may reuse their buffers across
// entries); copy what you need to retain. This contract lets scan-heavy
// callers walk large ranges without the backend allocating a fresh
// key/value slice per entry.
type Iterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Err() error
	Close() error
}

// RangedScanner is an OPTIONAL StorageBackend capability: a bounded scan that
// both starts at a known key and stops after a known number of keys.
//
// It exists for paginated callers, which need both halves. Resuming at a
// cursor: without startKey, each page re-resolves every key already consumed,
// so walking n keys in pages of size p costs O(n·n/p). Stopping at maxKeys:
// without it, a page that returns p keys still materializes all n, so the
// saving from seeking is immediately given back. Together they make a
// paginated walk O(n) in total rather than O(n·n/p).
//
// Both halves are cheap for a backend to honor: it already resolves the
// prefix range and can binary-search its sorted keys to startKey, and
// returning early from a merge is just stopping the loop.
//
// Implementations MUST return keys in ascending order, MUST include startKey
// itself when it is under the prefix (the cursor names the next key to
// return, not the last one already returned), and MUST return at most maxKeys
// entries. Callers must treat a backend that does not implement this as "not
// seekable" and fall back to scanning from the start themselves, so
// implementing it is never required.
type RangedScanner interface {
	// ScanFrom returns an Iterator over keys with the given prefix, starting
	// at the first such key >= startKey and yielding at most maxKeys entries.
	// An empty startKey means "from the first key under the prefix"; maxKeys
	// <= 0 means unlimited.
	ScanFrom(ctx context.Context, prefix, startKey []byte, maxKeys int) (Iterator, error)
}

// ErrRangeUnsupported is returned by a wrapper's ScanFrom when the backend it
// delegates to does not itself implement RangedScanner. Go interfaces cannot
// declare methods conditionally, so a wrapper that must stay a
// StorageBackend always *has* a ScanFrom method; returning this sentinel is
// how it says "not actually seekable". Callers should treat it as "fall back
// to scanning from the start" rather than as a failure.
var ErrRangeUnsupported = errors.New("storage: ranged scan not supported by backend")

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

package api

import "context"

// ShardStore is a Reed-Solomon-style erasure-coded shard store, ported
// from v1's erasure_coding.go/bitrot.go/healing.go. It is kept separate
// from StorageBackend/ObjectService: an object plugin wanting
// erasure-coded durability for large bodies would split the body into
// data+parity shards via this service instead of storing the raw body
// directly (see plugins/erasure's package doc for the integration
// sketch) — that wiring is a follow-up, not part of this interface.
type ShardStore interface {
	// StoreShards erasure-encodes and persists shards under id, replacing
	// any existing shard set for that id.
	StoreShards(ctx context.Context, id string, data []byte) error

	// ReadShards reconstructs and returns the original data for id,
	// tolerating up to the configured parity-shard count of missing or
	// corrupt shards.
	ReadShards(ctx context.Context, id string) (data []byte, err error)

	// VerifyShards checks every shard's stored hash against its content
	// without reconstructing anything, returning which shard indices (if
	// any) are corrupt or missing.
	VerifyShards(ctx context.Context, id string) (ok bool, corruptIndices []int, err error)

	// HealShards reconstructs any corrupt/missing shards for id from
	// parity and rewrites them in place. A no-op (returns nil) if nothing
	// is damaged.
	HealShards(ctx context.Context, id string) error
}

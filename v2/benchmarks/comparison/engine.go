// Package comparison holds market-comparison benchmarks: Velocity v2's KV
// engine (storage-lsm) measured head-to-head against two real embedded
// engines it competes with conceptually, SQLite and BoltDB, under the
// same operation counts, key/value sizes, and durability settings. This
// is a different exercise from the sibling v2/benchmarks package's
// internal microbenchmarks (which measure v2's own plugins in isolation,
// see ../RESULTS.md) — this package answers "how does v2 compare to
// engines already in the market," which v1 never did despite building
// benchmarks/sql_comparison for exactly that purpose (it built the
// harness but never committed a result).
//
// All three engines below run with real, comparable durability: fsync
// (or the engine's equivalent) enabled on every write, not each engine's
// fastest possible unsafe mode. See RESULTS.md for captured numbers and
// an honest reading of them.
package comparison

// KVEngine is the narrow interface every provider in this package
// implements, so head_to_head_test.go can drive all of them through one
// table-driven benchmark body.
type KVEngine interface {
	Put(key, value []byte) error
	Get(key []byte) (value []byte, ok bool, err error)
	Close() error
}

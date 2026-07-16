# Velocity Continuation Implementation Report

## Implemented in this pass

### Safe point reads

- `DB.Get` now returns caller-owned bytes instead of exposing mutable memtable storage.
- Added `DB.GetInto(key, dst)` for caller-buffer reuse and allocation-free result materialization when capacity is sufficient.
- Added `DB.Exists(key)` for existence checks without returning a value on memtable hits.
- Added `LRUCache.GetInto` to avoid the mandatory cache-hit allocation used by `LRUCache.Get`.

### Input and lifecycle hardening

Added stable errors:

- `ErrKeyNotFound`
- `ErrEmptyKey`
- `ErrKeyTooLarge`
- `ErrValueTooLarge`
- `ErrClosed`

Added enforced format limits:

- Maximum key size: 16 MiB
- Maximum direct KV value size: 1 GiB

Large payloads should use the object/blob subsystem rather than a single KV record.

Primary KV operations now reject use after close and reject malformed or unrepresentable record sizes before WAL/SSTable encoding.

### Write hot-path improvements

- Replaced `crc32.NewIEEE`/`hash.Hash` construction in normal and TTL writes with direct `crc32.ChecksumIEEE` + `crc32.Update` calls.
- TTL writes now capture the clock once, ensuring timestamp and expiry derive from the same instant.

### Regression coverage

Added coverage for:

- Empty and oversized key validation
- Oversized value validation without allocating a giant test value
- Caller-owned copy behavior for point reads

## Previously completed fixes retained

- WAL checkpoint preservation during concurrent memtable flushes
- Atomic persisted-prefix removal
- WAL write/sync failure buffer preservation
- WAL `0600` permissions
- Memtable ownership, rollback, tombstone accounting, expiry cleanup, and empty-key safety
- Integrity filesystem stub replacement

## Validation

`pkg/storage` tests passed under the locally available Go 1.23 toolchain while the module declaration was temporarily adjusted in the working copy. The declaration was restored to Go 1.26.0 before packaging.

A complete repository test remains blocked in this environment because external modules and the Go 1.26 toolchain cannot be downloaded. Run in a network-enabled Go 1.26 environment:

```bash
go test ./...
go test -race ./...
go test -run Test -count=20 ./...
go test -bench=. -benchmem ./...
(cd web && go test ./...)
```

## High-priority remaining work

1. Replace the `sync.Map` memtable with a sharded arena-backed mutable table and frozen immutable tables.
2. Introduce MVCC sequence numbers and snapshots.
3. Split the root `DB` into storage-kernel and service layers.
4. Consolidate overlapping object, secret, and V2 compatibility APIs.
5. Remove process-global signal ownership from the embedded library or make it explicitly opt-in.
6. Split oversized SQL, search, envelope, and object files by responsibility.
7. Add crash/fault-injection and protocol-conformance suites.
8. Add blob/value-log storage for large values.
9. Centralize governance, authorization, compliance, residency, retention, and audit enforcement.
10. Add reproducible benchmark baselines and profile-guided hot-path work.

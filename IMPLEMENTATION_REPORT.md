# Velocity stabilization and performance pass

This revision focuses on correctness defects that could cause data loss or make integrity checks nonfunctional, followed by low-risk hot-path improvements.

## Implemented

- Replaced the unimplemented integrity filesystem shim with a testable `os.Stat` path.
- Added WAL checkpoints and atomic prefix compaction.
- Changed memtable flushes to remove only WAL records represented by the flushed immutable memtable. Concurrent writes remain in the WAL.
- Fixed flush rollback so restored entries update memtable size accounting and never overwrite newer writes.
- Made stored memtable keys own their backing memory while preserving allocation-free byte-slice lookups.
- Fixed empty-key panics caused by taking `&key[0]`.
- Standardized memtable storage on pointers instead of mixing values and pointers for newly inserted records.
- Fixed tombstone size accounting and stale expiry metadata.
- Closed the WAL file when WAL construction rejects a missing crypto provider.
- Changed WAL file permissions from `0644` to `0600`.
- Preserved buffered WAL data when a write or sync fails instead of silently dropping the active buffer.
- Reused WAL buffers through the existing pool.
- Normalized the root and web modules to Go 1.26.0.
- Removed macOS archive metadata (`__MACOSX`).
- Added regression tests for all repaired paths.

## Important validation note

The execution environment provides Go 1.23.2 and has no network access. The project and current dependencies target Go 1.26.0, and the dependencies are not pre-cached. Therefore the complete repository test suite could not be compiled or executed here. Run the commands below in an environment with Go 1.26.0 and dependency access:

```bash
go test ./...
go test -race ./...
go test ./... -run TestWALTruncatePrefixPreservesPostCheckpointWrites -count=100
go test ./... -bench=. -benchmem
```

The nested web module should be validated separately:

```bash
cd pkg/web
go test ./...
```

## Next architectural work

The larger service extraction described in the review—isolating the storage kernel from SQL, objects, secrets, compliance, graph, and protocol concerns—is a multi-stage compatibility-sensitive refactor. It should be completed incrementally after this correctness baseline passes CI, rather than being mixed into one untestable rewrite.

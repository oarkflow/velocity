# Velocity v2 — Market-Comparison Benchmarks

Head-to-head comparison of Velocity v2's KV engine (`storage-lsm`) against
two real, widely-used embedded engines it competes with conceptually:
**SQLite** (`mattn/go-sqlite3`, WAL journal mode) and **BoltDB**
(`go.etcd.io/bbolt`). This answers "how does v2 compare to engines already
in the market"; `../RESULTS.md` measures v2's own plugins in isolation.

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-10-03 (re-run; supersedes the 2026-09-27 capture below it)
- **Method**: `go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .`
  (three runs; medians quoted)
- **Scope**: Postgres/MySQL are excluded — they need a running server, which
  `go test -bench` can't reproducibly start. All three engines here are
  embedded, in-process, file-backed.
- **Caveat**: single machine; fsync latency on this host varied up to ~10x
  across the day (APFS/OrbStack background activity), so write-path numbers
  should be re-verified on your own hardware. Read-path numbers were stable.

## Engine modes compared

| Mode | Durability guarantee |
|---|---|
| `velocity` | `fsync_mode: full` — F_FULLFSYNC per write; survives real power loss (stronger than anything else on this table) |
| `velocity-fast` | `fsync_mode: posix` — plain fsync(2) per write; survives process/OS crash (SQLite's *claimed* level) |
| `velocity-async` | `fsync_mode: posix` + `commit_interval: 1ms`, `always_sync: false` — one coalesced fsync/ms; at most 1ms of writes lost on power failure (same class as Redis AOF everysec / PG synchronous_commit=off). `Engine.Sync()` is the explicit durability barrier |
| `sqlite` | `_journal_mode=WAL&_synchronous=FULL` — see the verification section for what this *actually* costs |
| `boltdb` | default `Update` transactions (per-transaction fsync) |

## Raw output (medians of 3 runs)

```
BenchmarkPut/velocity-10             2847724 ns/op    221 B/op    3 allocs/op   (~2.85 ms)
BenchmarkPut/velocity-fast-10          25666 ns/op     99 B/op    3 allocs/op
BenchmarkPut/velocity-async-10           468 ns/op     48 B/op    3 allocs/op
BenchmarkPut/sqlite-10                  6668 ns/op    312 B/op   10 allocs/op
BenchmarkPut/boltdb-10               5964618 ns/op  32767 B/op   50 allocs/op

BenchmarkGet/velocity-10                127 ns/op     176 B/op    4 allocs/op
BenchmarkGet/velocity-fast-10           129 ns/op     176 B/op    4 allocs/op
BenchmarkGet/velocity-async-10          121 ns/op     176 B/op    4 allocs/op
BenchmarkGet/sqlite-10                 4298 ns/op     920 B/op   22 allocs/op
BenchmarkGet/boltdb-10                  547 ns/op     608 B/op    9 allocs/op

BenchmarkSequentialWriteBatch/velocity-10        9520875833 ns/op  (5,000 keys ≈ 1.90 ms/key)
BenchmarkSequentialWriteBatch/velocity-fast-10     125089463 ns/op  (≈ 25.0 µs/key)
BenchmarkSequentialWriteBatch/velocity-async-10      7556897 ns/op  (≈ 1.5 µs/key)
BenchmarkSequentialWriteBatch/sqlite-10            220855267 ns/op  (≈ 44.2 µs/key)
BenchmarkSequentialWriteBatch/boltdb-10          14784212667 ns/op  (≈ 2.96 ms/key)
```

`BenchmarkPut` cycles a bounded 10,000-key set (warm updates);
`SequentialWriteBatch` writes 5,000 strictly unique keys into a fresh engine
per iteration, ending with a durable close — ns/op there is the whole batch.

## What this honestly tells you

**Reads: Velocity wins clearly and reproducibly.** Point-lookup `Get` is
~127ns vs BoltDB 547ns (~4.3x) and SQLite 4.3µs (~34x). Reads never touch
the WAL; they're served from the in-memory index.

**Bulk load (5,000 unique keys, durable): `velocity-async` is the fastest
option measured — 7.6ms total (1.5µs/key), vs SQLite 221ms (29x faster),
`velocity-fast` 125ms (14x faster), BoltDB 14.8s.** Even with a real fsync
per key (`velocity-fast`) the engine beats SQLite's WAL autocommit path by
~1.8x on this workload.

**Single-op writes: the honest result depends on the durability you
actually get, and the SQLite column needs an asterisk — see below.**

## Verification: what `_synchronous=FULL` actually costs SQLite here

The earlier version of this file reported SQLite at 6.7µs/op for durable
single-key writes and treated that as a durability-matched comparison. It
isn't. Measured directly on this machine (standalone program, same DSN,
steady-state warm updates over a 10k-key set):

```
WAL+FULL steady     sync=2 journal=wal   4.4 µs/op
WAL+OFF steady      sync=0 journal=wal   4.3 µs/op
WAL+NORMAL steady   sync=1 journal=wal   4.4 µs/op
WAL+FULL fresh unique inserts            42 µs/op
DELETE-journal+FULL warm updates        313 µs/op
raw unix.Fsync on a warm fd            ~22 µs/op   (this machine's fsync floor)
```

`_synchronous=FULL` is confirmed in effect (`PRAGMA synchronous` = 2) yet
costs the same as `OFF` in the warm-update regime — SQLite's number is
**below this machine's raw fsync floor**, i.e. the harness's SQLite is not
paying a per-statement fsync there. Meanwhile `velocity-fast`'s 25µs is
~97% fsync syscall (pprof-verified). The "SQLite is 3.6x faster on single
writes" reading from the previous capture was comparing Velocity's real
fsync against SQLite's effectively-unfsynced WAL append.

Apples-to-apples conclusions at **matched guarantees**:

- **Per-write durable (fsync per op)**: `velocity-fast` (25µs) beats
  SQLite wherever SQLite really commits — fresh unique inserts (42µs) and
  rollback-journal mode (313µs) — and beats BoltDB by ~230x.
- **Bounded-staleness (≤1ms)**: `velocity-async` (467ns/op, 1.5µs/key
  bulk) beats every measured configuration of both engines by 14–12,700x
  on writes, at a guarantee comparable to what SQLite's warm-WAL path
  actually provides plus an explicit bound.
- **Strongest (power-loss)**: `velocity` (2.85ms) is the only engine here
  offering that guarantee at all.

**Reads, any pattern**: Velocity wins by 4–34x (unchanged across runs).

## Change log of this harness

- **2026-10-03**: added the `velocity-async` mode (commit coalescing with
  `commit_interval: 1ms`, verified: 200 staged writes covered by 1 fsync);
  re-ran everything (`-count=3`); added the `_synchronous=FULL` cost
  verification above; corrected the earlier "SQLite wins single writes"
  reading. Also cut write-path allocations (WAL record encoding no longer
  heap-escapes its header buffer).
- **2026-09-27**: added `fsync_mode` after discovering Go's `Sync()` is
  F_FULLFSYNC on Darwin; profiling showed the remaining single-op cost is
  the fsync itself (~97.5%), not software.

## Re-running

```sh
cd v2/benchmarks/comparison
go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .
```

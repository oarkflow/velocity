# Velocity v2 — Benchmark Results

Real numbers from `go test -bench=. -benchmem`, run in-process against the
actual plugin implementations (booted through the same `kernel.Boot` path
production uses — no shortcuts), not estimates.

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-10-03 (re-run with `-count=3`; medians quoted. Supersedes
  the 2026-09-27 capture)
- **Method**: `go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .`
- **Caveats**: single machine. Write-path timings on this host varied up to
  ~10x across the day (APFS background activity), so treat durable-write
  numbers as order-of-magnitude and re-verify on your hardware. Two
  numbers in the 2026-09-27 capture (`ObjectGet_1MB` at 44.7µs,
  `KVPut_StorageLSM` at 6.4µs) could not be reproduced on any code state
  checked (committed HEAD or working tree) and are corrected below —
  flagged explicitly rather than quietly dropped.

## Raw output (medians of 3)

```
BenchmarkEncrypt_XChaCha20_1KB     2129 ns/op    481 MB/s    2328 B/op   3 allocs/op
BenchmarkEncrypt_XChaCha20_1MB  1358390 ns/op    772 MB/s  2113570 B/op   3 allocs/op
BenchmarkDecrypt_XChaCha20_1KB    1644 ns/op    623 MB/s    1024 B/op   1 allocs/op
BenchmarkDecrypt_XChaCha20_1MB  1173975 ns/op    893 MB/s  1048580 B/op   1 allocs/op
BenchmarkEncrypt_FIPS_1KB          856 ns/op   1197 MB/s    2320 B/op   3 allocs/op
BenchmarkEncrypt_FIPS_1MB       325515 ns/op   3221 MB/s  2113561 B/op   3 allocs/op
BenchmarkDecrypt_FIPS_1KB          353 ns/op   2900 MB/s    1024 B/op   1 allocs/op
BenchmarkDecrypt_FIPS_1MB       222908 ns/op   4704 MB/s  1048581 B/op   1 allocs/op

BenchmarkKVPut_StorageLSM         3620 ns/op    2888 B/op     32 allocs/op
BenchmarkKVPut_StorageMem          575 ns/op     376 B/op      5 allocs/op
BenchmarkKVGet_StorageLSM          176 ns/op     160 B/op      4 allocs/op
BenchmarkKVGet_StorageMem          155 ns/op     151 B/op      3 allocs/op
BenchmarkKVDelete_StorageLSM      2076 ns/op    1277 B/op     17 allocs/op
BenchmarkKVDelete_StorageMem       341 ns/op      39 B/op      2 allocs/op
BenchmarkKVScan_StorageLSM     28514886 ns/op  35909657 B/op  59979 allocs/op  (5,000-key prefix)
BenchmarkKVScan_StorageMem     20482391 ns/op  10462444 B/op  112976 allocs/op

BenchmarkObjectPut_1KB          3660930 ns/op    6873 B/op     38 allocs/op
BenchmarkObjectPut_64KB         5552594 ns/op  185603 B/op     57 allocs/op
BenchmarkObjectPut_1MB         23545987 ns/op 10134119 B/op    273 allocs/op
BenchmarkObjectPut_1KB_fast      121235 ns/op    8950 B/op     53 allocs/op   (fsync_mode: posix)
BenchmarkObjectPut_1MB_fast    36280498 ns/op 11699910 B/op    307 allocs/op   (noisy, see below)
BenchmarkObjectGet_1KB            3200 ns/op    3085 B/op     15 allocs/op
BenchmarkObjectGet_64KB          68251 ns/op  180323 B/op     18 allocs/op
BenchmarkObjectGet_1MB          916286 ns/op  3189110 B/op     54 allocs/op
BenchmarkObjectList             4224164 ns/op  1697528 B/op   5072 allocs/op

BenchmarkFullTextIndex           32329 ns/op    8291 B/op    114 allocs/op
BenchmarkFullTextQuery         8162161 ns/op  4777679 B/op  10315 allocs/op  (2,000 docs)
BenchmarkVectorUpsert_Dim12    1522798 ns/op  186374 B/op   1650 allocs/op
BenchmarkVectorSearch_1000      226807 ns/op   51470 B/op    466 allocs/op
BenchmarkVectorSearch_10000     188221 ns/op   79766 B/op    492 allocs/op

BenchmarkSQLInsert               17392 ns/op    9425 B/op    127 allocs/op
BenchmarkSQLSelectByPK            4151 ns/op    1785 B/op     32 allocs/op
BenchmarkSQLSelectWhereScan    14201427 ns/op 10968916 B/op  147744 allocs/op  (10,000 rows)
```

## What this tells you

**Crypto**: FIPS AES-GCM is ~2-5x faster than XChaCha20-Poly1305 on Apple
Silicon (hardware AES, no hardware ChaCha) — e.g. 1MB decrypt 4704 vs 893
MB/s. Pick via the manifest; this is a per-deployment choice, not a fixed
trade-off.

**KV**: Put on `storage-lsm` (no per-write fsync; batched WAL + checkpoint
durability) is ~6x slower than `storage-mem` (3.6µs vs 0.6µs) — the WAL
append + memtable cost. Get is backend-independent (~176ns) since reads
never touch the WAL. Durable per-write costs (fsync) are in
`../comparison/RESULTS.md`, where the durability modes are compared
honestly against other engines.

**KV Scan (5,000-key prefix)**: ~28ms on storage-lsm with 35.9MB / 60k
allocs — the map-materializing `kv.Scan` API is the cost, not storage.
SQL's scan paths now stream (`api.KVStreamScanner`) instead; the KV-level
`Scan` (map API) remains the heavy variant by design. Still an open
optimization target for callers that need whole-prefix maps.

**Object storage**: Put cost is dominated by ONE durable commit per
PutObject (metadata + every block in a single storage `Batch`) — the
`_fast` variants prove it: `fsync_mode: posix` drops 1KB Put from ~3.7ms
to ~0.12ms (~30x) with no other change. The 2026-09-27 claim that this was
"versioning/metadata bookkeeping cost" was wrong; CPU profiles attribute
>80% of it to the fsync syscall (F_FULLFSYNC on Darwin). `ObjectPut_1MB_fast`
is deliberately reported as measured (noisy, 22-45ms across runs) — a 1MB
WAL append + fsync on this host is where the day's fsync jitter shows most.
`ObjectGet_1MB` is ~0.9ms (4 blocks of 256KB); the 2026-09-27 figure of
44.7µs was not reproducible on any code state (it predates per-block range
storage) and is retracted.

**Search**: full-text Index ~32µs/doc. Full-text Query over 2,000 docs is
8.2ms — slower than the 3.5ms of the 09-27 capture and not explained by
code changes (no search-plugin changes between); reported as measured. HNSW
vector Search scales sub-linearly: 227µs at 1k vectors, 188µs at 10k
(10x data, no latency growth — matching the plugin's 100% recall tests).

**SQL**: `SELECT ... WHERE age > 50` over 10,000 rows is **14.2ms**
(previously 49-55ms) after switching full-table and index walks to the
streaming KV scan path — 3.5x faster and 4x fewer bytes allocated
(11MB vs 45MB). Point SELECT by PK is 4.2µs. SQLInsert is 17µs including
amortized memtable flush/compaction.

## What changed since 2026-09-27 (and why the numbers moved)

- **storage-lsm rework** (landed): streaming sstWriter, refcounted
  pread-based sstables, size-tiered compaction, lazy value reads on scan.
- **WAL record encoding** is now allocation-free (the header scratch no
  longer heap-escapes through `bufio.Writer.Write`; `readRecord` uses one
  combined key/value allocation + `crc32.Update` instead of three
  allocations + a hash object). KVPut writes: 57 → 32 allocs/op; compaction
  merges scale with it.
- **Commit coalescing** (`commit_interval`): see
  `../comparison/RESULTS.md` — 200 staged writes covered by 1 fsync.
- **Streaming scans** (`api.KVStreamScanner`): SQL scan 49ms → 14ms.
- Two 09-27 figures (`ObjectGet_1MB` 44.7µs, `KVPut` 6.4µs/672B/14 allocs)
  could not be reproduced and are superseded by the table above.

## Re-running

```sh
cd v2/benchmarks
go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .
```

For statistical rigor across code changes, use `-count=10` and
[`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).

# Velocity v2 — Benchmark Results

Real numbers from `go test -bench=. -benchmem`, run in-process against the
actual plugin implementations (booted through the same `kernel.Boot` path
production uses — no shortcuts), not estimates.

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-10-16 (re-run with `-count=3`; medians quoted. Supersedes
  the 2026-10-03 capture)
- **Method**: `go test -bench=. -benchmem -benchtime=0.5s -count=3 -run=^$ .`
- **Caveats**: single machine. Write-path timings on this host varied up to
  ~10x across the day (APFS background activity) — durable-write numbers
  (especially `ObjectPut_1MB_fast`, below) are order-of-magnitude only and
  re-verify on your hardware. Dependencies were also refreshed between the
  10-03 and 10-16 captures (`bcl` v0.0.36→v0.0.37, `x/crypto` v0.57→v0.58,
  `x/sys` v0.48→v0.49, `x/text` v0.42→v0.43), so paths that received **no**
  code changes still moved (KV get/delete totals dropped by 1-2 allocs,
  `KVScan` ~3.8x, `ObjectGet_64KB` ~2.2x, vector upsert ~1.7x); an A/B
  benchmark against the pre-optimization code on today's dependency set
  confirmed the same deviations, so those deltas are attributed to the
  dependency refresh + machine state, **not** to the optimization work
  described below. Only the deltas explained in "What changed" carry that
  claim.

## Raw output (medians of 3)

```
BenchmarkEncrypt_XChaCha20_1KB     2043 ns/op    501 MB/s    2328 B/op   3 allocs/op
BenchmarkEncrypt_XChaCha20_1MB  1295245 ns/op    795 MB/s  2113568 B/op   3 allocs/op
BenchmarkDecrypt_XChaCha20_1KB    2052 ns/op    507 MB/s    1024 B/op   1 allocs/op
BenchmarkDecrypt_XChaCha20_1MB  1551335 ns/op    676 MB/s  1048580 B/op   1 allocs/op
BenchmarkEncrypt_FIPS_1KB          870 ns/op   1177 MB/s    2320 B/op   3 allocs/op
BenchmarkEncrypt_FIPS_1MB        317210 ns/op   3306 MB/s  2113561 B/op   3 allocs/op
BenchmarkDecrypt_FIPS_1KB          355 ns/op   2887 MB/s    1024 B/op   1 allocs/op
BenchmarkDecrypt_FIPS_1MB        215575 ns/op   4864 MB/s  1048581 B/op   1 allocs/op

BenchmarkKVPut_StorageLSM         2144 ns/op    1197 B/op      6 allocs/op
BenchmarkKVPut_StorageMem          411 ns/op     351 B/op      5 allocs/op
BenchmarkKVGet_StorageLSM          143 ns/op     144 B/op      2 allocs/op
BenchmarkKVGet_StorageMem          132 ns/op     143 B/op      2 allocs/op
BenchmarkKVDelete_StorageLSM      1756 ns/op     975 B/op      7 allocs/op
BenchmarkKVDelete_StorageMem       315 ns/op      39 B/op      2 allocs/op
BenchmarkKVScan_StorageLSM      7431156 ns/op  4695887 B/op  10658 allocs/op  (5,000-key prefix)
BenchmarkKVScan_StorageMem      7320984 ns/op  4464575 B/op  15677 allocs/op

BenchmarkObjectPut_1KB          2848041 ns/op     7312 B/op     38 allocs/op
BenchmarkObjectPut_64KB         3476815 ns/op   147132 B/op     52 allocs/op
BenchmarkObjectPut_1MB         10765613 ns/op  7396737 B/op    126 allocs/op
BenchmarkObjectPut_1KB_fast      56271 ns/op     9775 B/op     41 allocs/op   (fsync_mode: posix)
BenchmarkObjectPut_1MB_fast    21652085 ns/op 11951256 B/op    152 allocs/op   (noisy, see below)
BenchmarkObjectGet_1KB            2659 ns/op     3089 B/op     15 allocs/op
BenchmarkObjectGet_64KB          29612 ns/op   179911 B/op     17 allocs/op
BenchmarkObjectGet_1MB           350615 ns/op  3180748 B/op     38 allocs/op
BenchmarkObjectList             2098210 ns/op  1483477 B/op   3069 allocs/op

BenchmarkFullTextIndex           14549 ns/op     8963 B/op     74 allocs/op
BenchmarkFullTextQuery           70845 ns/op     2433 B/op     21 allocs/op  (2,000 docs)
BenchmarkVectorUpsert_Dim12     878562 ns/op   182135 B/op   1620 allocs/op
BenchmarkVectorSearch_1000      163262 ns/op    52262 B/op    490 allocs/op
BenchmarkVectorSearch_10000     208505 ns/op    80736 B/op    510 allocs/op

BenchmarkSQLInsert               14355 ns/op     4921 B/op     66 allocs/op
BenchmarkSQLSelectByPK            3662 ns/op     1685 B/op     25 allocs/op
BenchmarkSQLSelectWhereScan   11057528 ns/op  10891620 B/op  98425 allocs/op  (10,000 rows)
```

## What this tells you

**Crypto**: FIPS AES-GCM is ~2-5x faster than XChaCha20-Poly1305 on Apple
Silicon (hardware AES, no hardware ChaCha) — e.g. 1MB decrypt 4864 vs 676
MB/s. Pick via the manifest; this is a per-deployment choice, not a fixed
trade-off.

**KV**: Put on `storage-lsm` (no per-write fsync; batched WAL + checkpoint
durability) is ~5x slower than `storage-mem` (2.1µs vs 0.4µs) — the WAL
append + memtable cost. Get is backend-independent (~143ns) since reads
never touch the WAL. Durable per-write costs (fsync) are in
`../comparison/RESULTS.md`, where the durability modes are compared
honestly against other engines.

**KV Scan (5,000-key prefix)**: ~7.4ms on storage-lsm with 4.7MB / 10.6k
allocs — the map-materializing `kv.Scan` API is the cost, not storage.
SQL's scan paths stream (`api.KVStreamScanner`) instead; the KV-level
`Scan` (map API) remains the heavy variant by design. Still an open
optimization target for callers that need whole-prefix maps.

**Object storage**: Put cost is dominated by ONE durable commit per
PutObject (metadata + every block in a single storage `Batch`) — the
`_fast` variants prove it: `fsync_mode: posix` drops 1KB Put from ~2.8ms
to ~55µs (~50x) with no other change. `ObjectPut_1MB_fast` is deliberately
reported as measured (noisy, 12-23ms across runs) — a 1MB WAL append +
fsync on this host is where the day's fsync jitter shows most. `ObjectGet`
improved alongside the KV/dependency layer (1MB: 0.92ms → 0.35ms); code on
the Get path did not change.

**Search**: full-text Query over 2,000 docs is now **~71µs / 21 allocs**
down from 8.2ms / 10,315 allocs (~115x, ~490x fewer allocs) — the entire
postings walk happens against an in-memory index instead of per-key KV
fetches, with a bounded top-k heap on the hot path (see "What changed").
Index throughput is 14.5µs/doc at 74 allocs, equal-or-better than the
10-03 figure (32µs/114). HNSW vector Search scales sub-linearly: 163µs at
1k vectors, 209µs at 10k (10x data, barely any latency growth — matching
the plugin's 100% recall tests).

**SQL**: `SELECT ... WHERE age > 50` over 10,000 rows is **11.1ms**
(previous capture 14.2ms; pre-optimization on the same dependency set,
~17.4ms) with 98,425 allocs vs 147,744 (-33%). The win is a hand-rolled
row-JSON decoder replacing `encoding/json` on every row decode, a
qualified-key concatenation cache, and allocation-free range-index entry
decoding (see "What changed"). Point SELECT by PK is 3.7µs. SQLInsert is
14µs including amortized memtable flush/compaction.

## What changed since 2026-10-03

Four optimization tracks, each verified by dedicated parity tests (every
new path is tested against the old-path or independently-computed ground
truth, plus `-race`):

- **Search: in-memory postings index** (`plugins/search`). The full-text
  plugin now maintains an in-memory postings map (warmed lazily from KV on
  first query; Index/Remove before warmup queue into `pendingUpdates`).
  Matching walks term → smallest posting list, phrases fetch their KV keys
  as before, and results finalize through a bounded top-k heap.
  Trade-offs are stated in `plugins/search/fulltext.go`: phrasal matching
  is deliberately NOT cached (per-key KV fetch kept), and the config knob
  `search.in_memory_index: false` reverts to the pure scan path. Memory is
  bounded by the corpus, not query count. This is the FullTextQuery
  8.2ms → 71µs change.

- **SQL: hand-rolled row JSON decoder** (`plugins/sql/rowdecode.go`).
  Every row returned by a scan/join was unmarshalled through
  `encoding/json`; `decodeRowJSON` parses the flat-row layout directly
  (single scratch buffer, per-field error location, byte-level string
  scanning). Parity-tested against `encoding/json` on flat, composite,
  escaped, and malformed inputs, so it returns identical rows AND
  identical error messages (`rowJSONErr` deliberately unmarshals into
  `api.Row` to keep error text byte-identical).

- **SQL: qualified-key concat cache** (`plugins/sql/exec.go`, `join.go`).
  Qualifying row keys (needed by correlated subqueries and
  `resolve()`-selected qualified names) used to allocate a fresh
  `"table.column"` string per row per column; a small per-row cache
  (`newQualifiedKeyCache`) reuses the backed bytes. The unqualified-first
  ordering was kept exactly as before: qualified lookups still resolve
  before bare ones, so correlated references mis-resolving if the cache
  ever skipped `qualifyRow` would be a live bug — it does not.

- **SQL: allocation-free range-index entry decode + streaming early
  stop** (`plugins/sql/range_index.go`). Numeric sortable entries are
  decoded by manual bit assembly (no `[]byte`→interface boxing); the
  walk stops at an entry whose decoded ordering key is past the query's
  high bound — valid ONLY on the streaming path (`ScanKeysStream` yields
  ascending keys); the paged `kv.Scan` path materializes maps with random
  iteration order and decodes-filter everything. Verified by
  `TestRangeQuery_MatchesFullScanExactly` (caught exactly this bug during
  development).

- A follow-on **ListObjects** micro-fix (`plugins/object`): suffix-latest
  filters use `bytes.HasSuffix` on the iterator's bytes instead of a
  string allocation per key (`ObjectList`: 4.22ms/5,072 allocs →
  2.10ms/3,069).

The SQL row-alloc figures should be read only as symptomatic of the
decode path — the where-scan 14.2 → 11.1ms and 147,744 → 98,425 allocs
number combine decoder + concat cache + range index changes.

## Re-running

```sh
cd v2/benchmarks
GOWORK=off go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .
```

For statistical rigor across code changes, use `-count=10` and
[`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).

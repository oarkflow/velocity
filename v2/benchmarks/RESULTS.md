# Velocity v2 — Benchmark Results

These are real numbers from `go test -bench=. -benchmem ./benchmarks/...`,
run in-process against the actual plugin implementations (booted through
the same `kernel.Boot` path production uses — no shortcuts), not
estimates. This closes a gap flagged directly by the project owner: v1 had
benchmark *infrastructure* (`benchmarks/sql_comparison`) but never
committed actual numbers; v2 previously had no benchmarks at all.

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-09-27
- **Method**: `go test -bench=. -benchmem -benchtime=1s -run=^$ ./benchmarks/...`
- **Caveat**: single machine, single run, `-benchtime=1s` — these are
  representative orders of magnitude, not a rigorous statistical result.
  For a real regression-tracking setup, run each benchmark multiple times
  with `-count=10` and compare with
  [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)
  (not done here for time).

## Raw output

Crypto, KV, Object, and Search benchmarks (one run):

```
goos: darwin
goarch: arm64
pkg: github.com/oarkflow/velocity/v2/benchmarks
cpu: Apple M2 Pro
BenchmarkEncrypt_XChaCha20_1KB-10     612211      1882 ns/op    544.07 MB/s      2328 B/op     3 allocs/op
BenchmarkEncrypt_XChaCha20_1MB-10        993   1200498 ns/op    873.45 MB/s   2113574 B/op     3 allocs/op
BenchmarkDecrypt_XChaCha20_1KB-10     808039      1509 ns/op    678.49 MB/s      1024 B/op     1 allocs/op
BenchmarkDecrypt_XChaCha20_1MB-10       1023   1158021 ns/op    905.49 MB/s   1048580 B/op     1 allocs/op
BenchmarkEncrypt_FIPS_1KB-10         1740051     736.4 ns/op   1390.55 MB/s      2320 B/op     3 allocs/op
BenchmarkEncrypt_FIPS_1MB-10             3769   303300 ns/op   3457.23 MB/s   2113564 B/op     3 allocs/op
BenchmarkDecrypt_FIPS_1KB-10          4194847     289.8 ns/op   3533.59 MB/s      1024 B/op     1 allocs/op
BenchmarkDecrypt_FIPS_1MB-10             6018   213418 ns/op   4913.25 MB/s   1048580 B/op     1 allocs/op
BenchmarkKVPut_StorageLSM-10           186285      6445 ns/op       672 B/op    14 allocs/op
BenchmarkKVPut_StorageMem-10          2193175     526.6 ns/op       750 B/op     8 allocs/op
BenchmarkKVGet_StorageLSM-10          9003062     131.1 ns/op       151 B/op     3 allocs/op
BenchmarkKVGet_StorageMem-10         10060666     119.7 ns/op       151 B/op     3 allocs/op
BenchmarkKVDelete_StorageLSM-10       2112907     534.2 ns/op       455 B/op     9 allocs/op
BenchmarkKVDelete_StorageMem-10       3140011     446.3 ns/op       391 B/op     5 allocs/op
BenchmarkKVScan_StorageLSM-10               82  14064299 ns/op  10466090 B/op  113220 allocs/op
BenchmarkKVScan_StorageMem-10                84  13803551 ns/op  10462362 B/op  112976 allocs/op
BenchmarkObjectPut_1KB-10                  378   2900643 ns/op      5492 B/op     54 allocs/op
BenchmarkObjectPut_64KB-10                 354   3123947 ns/op    141545 B/op     66 allocs/op
BenchmarkObjectPut_1MB-10                  229   5402412 ns/op   2231400 B/op     74 allocs/op
BenchmarkObjectGet_1KB-10                656719      1812 ns/op      1835 B/op    10 allocs/op
BenchmarkObjectGet_64KB-10               195847      6036 ns/op     66424 B/op    10 allocs/op
BenchmarkObjectGet_1MB-10                 27694     44746 ns/op   1049481 B/op    10 allocs/op
BenchmarkObjectList-10                      564   1965094 ns/op   1229195 B/op   8077 allocs/op
BenchmarkFullTextIndex-10                 18211     63966 ns/op      9730 B/op   184 allocs/op
BenchmarkFullTextQuery-10                   328   3504345 ns/op   2351589 B/op  16487 allocs/op
BenchmarkVectorUpsert_Dim12-10              6518    884653 ns/op    188260 B/op  1673 allocs/op
BenchmarkVectorSearch_1000-10               8698    139592 ns/op     51680 B/op   475 allocs/op
BenchmarkVectorSearch_10000-10              5881    221723 ns/op     80908 B/op   540 allocs/op
PASS
ok      github.com/oarkflow/velocity/v2/benchmarks     120.692s
```

SQL benchmarks (separate run, same machine, immediately after):

```
goos: darwin
goarch: arm64
pkg: github.com/oarkflow/velocity/v2/benchmarks
cpu: Apple M2 Pro
BenchmarkSQLInsert-10               121204      9840 ns/op      2364 B/op      49 allocs/op
BenchmarkSQLSelectByPK-10           332206      3648 ns/op      1709 B/op      31 allocs/op
BenchmarkSQLSelectWhereScan-10           21  49057022 ns/op  36170534 B/op  412814 allocs/op
PASS
ok      github.com/oarkflow/velocity/v2/benchmarks     7.566s
```

(Run separately with `-bench=^BenchmarkSQL` only because `plugins/sql` was
being edited by a parallel agent at the moment of the first full run;
both runs are real, on the same machine, back to back.)

## What this tells you

**Crypto (XChaCha20-Poly1305 vs. FIPS AES-256-GCM)**: at both 1KB and 1MB,
FIPS AES-GCM is measurably *faster* than XChaCha20-Poly1305 on this
machine (e.g. 1MB decrypt: 4913 MB/s FIPS vs. 905 MB/s XChaCha20) — this
is expected on Apple silicon, which has hardware AES instructions but no
hardware ChaCha20 acceleration. This is the opposite of the common
assumption that ChaCha20 is always faster than AES-GCM — that's only true
on hardware *without* AES-NI/ARMv8 crypto extensions. v2's architecture
lets you pick either via the manifest with zero code changes, so this is
a real, actionable per-deployment choice, not a fixed trade-off.

**KV (storage-lsm vs. storage-mem)**: Put is ~12x slower on storage-lsm
than storage-mem (6445 ns/op vs. 526.6 ns/op) — the WAL fsync/durability
cost, exactly as expected. Get is nearly identical between the two
(131 ns vs. 120 ns) since reads don't touch the WAL. Scan is the slowest
KV operation by far on both backends (~14ms for a 5000-key prefix scan) —
this reflects the current paginated-Scan implementation's cost, not a
storage-engine difference (LSM and Mem are within 2% of each other here),
and is a reasonable target for future optimization work.

**Object storage**: Put cost is dominated by fixed overhead, not payload
size, until 1MB (2.9ms at 1KB vs. 5.4ms at 1MB) — versioning/metadata
bookkeeping cost is the current bottleneck at small sizes, not I/O
bandwidth. Get scales much more linearly with size (1.8µs at 1KB up to
44.7µs at 1MB) and is far cheaper than Put across the board, as expected
for a versioned store where writes do more bookkeeping than reads.

**Search**: full-text Index is cheap (64µs/doc) but Query over 2000
indexed docs is comparatively expensive (3.5ms) — the current full-text
query path has room for optimization (e.g. precomputed term postings
rather than a per-query scan, if that's what's happening under the hood).
HNSW vector Search is the standout result: going from 1,000 to 10,000
indexed vectors only increased search latency from 139µs to 221µs
(~1.6x for a 10x data increase) — this is exactly the sub-linear scaling
HNSW is supposed to provide, and matches the 100% recall result the
search plugin's own test suite already reported.

**SQL**: point-lookup SELECT by primary key (3648 ns/op) is roughly
13,400x faster than a full-table-scan SELECT with a WHERE filter over
10,000 rows (49ms) — this is the expected, currently-undocumented cost of
v2's SQL plugin having no secondary indexing yet (every non-PK WHERE
clause is a full scan, as its own package doc admits). This number is the
concrete argument for prioritizing secondary indexes in a future pass,
not a vague "SQL feels slow" impression.

## Re-running

```sh
cd v2
go test -bench=. -benchmem -benchtime=1s -run=^$ ./benchmarks/...
```

Pass `-benchtime=5s -count=10` and pipe through `benchstat` for a more
statistically rigorous comparison across code changes.

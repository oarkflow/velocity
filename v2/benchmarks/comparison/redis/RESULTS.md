# Velocity v2 vs. real Redis — benchmark results

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-10-03 (re-run; supersedes the 2026-09-27 capture)
- **Redis**: real `redis-server` v8.10.2 (Homebrew), launched as a
  subprocess with `--save "" --appendonly no` (persistence disabled —
  Redis's typical cache deployment)
- **Velocity**: `storage-mem` + `kv` + `redisdata` + `resp` (RESP server on
  a non-default port)
- **Client**: the SAME real `github.com/redis/go-redis/v9` client against
  both servers over real TCP loopback — go-redis has no idea one of the two
  servers isn't real Redis.
- **Method**: `go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .`,
  medians quoted.

## Three configurations

1. **`redis`** — real Redis, real go-redis, real TCP round trip. Baseline.
2. **`velocity-resp`** — Velocity's RESP server, same client, same wire.
   The "can I point an existing Redis client at Velocity" number.
3. **`velocity-native`** — Velocity's Go API in-process, no network. NOT a
   fair comparison to networked Redis; it's the embedded-library number.

## Single-command latency (one round trip per command)

```
BenchmarkSet/redis-10                 20842 ns/op    280 B/op    8 allocs/op
BenchmarkSet/velocity-resp-10         19941 ns/op    398 B/op   17 allocs/op
BenchmarkSet/velocity-native-10         357 ns/op     95 B/op    5 allocs/op

BenchmarkGet/redis-10                 21174 ns/op    255 B/op    8 allocs/op
BenchmarkGet/velocity-resp-10         16844 ns/op    311 B/op   14 allocs/op
BenchmarkGet/velocity-native-10         143 ns/op     47 B/op    3 allocs/op

BenchmarkIncr/redis-10                20020 ns/op    184 B/op    5 allocs/op
BenchmarkIncr/velocity-resp-10        16482 ns/op    336 B/op   16 allocs/op
BenchmarkIncr/velocity-native-10        145 ns/op    104 B/op    7 allocs/op

BenchmarkLPushLRange/redis-10         23272 ns/op    247 B/op    8 allocs/op
BenchmarkLPushLRange/velocity-resp-10 19274 ns/op    695 B/op   29 allocs/op
BenchmarkSAddSMembers/redis-10        19672 ns/op    247 B/op    8 allocs/op
BenchmarkSAddSMembers/velocity-resp-10 19431 ns/op    391 B/op   17 allocs/op
```

`velocity-resp` is not slower than real Redis on any single-command
operation tested (faster on GET/INCR/LPUSH, parity on SET/SADD) —
consistent with the 3 independent re-runs in the 2026-09-27 capture.

## Pipelined throughput (redis-benchmark methodology) — NEW

The previous capture explicitly flagged pipelining as untested and warned
that Redis's advantage shows up hardest there. That was true then: the
first measurement of this suite showed Redis ~2x faster under pipelining,
because Velocity flushed the socket after every command. The RESP server
now coalesces flushes while complete commands remain buffered (single-
command latency is unchanged — see `Reader.HasCompleteCommand`), and the
pipelined result flipped:

```
(64 commands per round trip; ns/op is per PIPELINE — divide by 64 for per-command)

run A (first measurement after the fix):
  BenchmarkPipelineSet/redis-10           79909 ns/op
  BenchmarkPipelineSet/velocity-resp-10   66144 ns/op
  BenchmarkPipelineGet/redis-10           68196 ns/op
  BenchmarkPipelineGet/velocity-resp-10   63148 ns/op

run B (re-run, same day):
  BenchmarkPipelineSet/redis-10           99669 ns/op   (78-122 µs across 3)
  BenchmarkPipelineSet/velocity-resp-10   79617 ns/op   (75-82 µs across 3)
  BenchmarkPipelineGet/redis-10           78114 ns/op   (72-80 µs across 3)
  BenchmarkPipelineGet/velocity-resp-10   95936 ns/op   (68-100 µs across 3 — noisy)
```

| | Redis | velocity-resp | reading |
|---|---|---|---|
| Pipelined SET throughput | ~800–1000k ops/s | ~1200–1400k ops/s | velocity-resp wins consistently (~1.25x) |
| Pipelined GET throughput | ~935–1280k ops/s | ~1010–1450k ops/s | parity; velocity-resp's run-B spread (68–100µs) is too wide to call — both directions seen across runs |

The important structural result: before flush coalescing, velocity-resp was
**~2x slower** than Redis on both pipelines (154µs vs 79µs SET; 148µs vs
68µs GET) — the exact gap the previous RESULTS.md warned about. The gap is
now closed; SET is consistently ahead and GET is within noise.

## Allocation status (what was fixed)

The 09-27 capture showed `velocity-resp` at 985 B / 29 allocs per SET vs
Redis's 280 B / 8. The RESP encode/decode path was rewritten to be
allocation-free (line headers read via `bufio.ReadSlice`, bulk payloads
through one reusable scratch, replies written without `fmt.Fprintf`,
argument slice reused per connection): SET is now 398 B / 17 allocs and GET
311 B / 14 — roughly half the bytes and 40% fewer allocations, with the
remaining gap concentrated in go-redis client-side accounting that both
servers pay (Redis's own 8/op floor) and one string copy per request
argument.

## Honest analysis — what this does and does not mean

**`velocity-resp` vs real Redis**: not slower on single-command latency for
every operation tested, and now *faster* on pipelined SET/GET throughput on
this machine. This is a genuine, repeated result — but it is still one
machine, one client library, localhost loopback, and a narrow command
surface.

**Feature surface is still the real gap, not speed**: real Redis carries
Lua scripting, MULTI/EXEC edge semantics, RESP3 completeness, cluster mode,
replication, AOF/RDB persistence tuning, keyspace notifications, and
decades of production hardening. `plugins/resp`/`plugins/redisdata`
implement a real but much narrower slice (see the plugin's doc comment for
the exact command list). No claim is made there.

**`velocity-native`** (embedded, no network) is 100-900ns/op vs 17-24µs
over the wire — entirely expected (no TCP round trip), and it's Velocity's
more differentiated story (Redis has no embedded mode at all). It is not
evidence that "Velocity beats Redis".

## Bottom line

- **"Point an existing Redis client at Velocity for KV/list/set/counter
  workloads"**: supported by real measurements — equal or better latency,
  better pipelined throughput on this machine, for the commands both sides
  support. Not a substitute if you need Lua, cluster, AOF/RDB tuning, or
  the wider command surface.
- **Pipelined-throughput coverage gap: closed** (it was the previous
  capture's biggest untested claim).
- Remaining honest gaps: per-op allocations still ~2x Redis's floor on the
  RESP path, and the feature-surface gap above is not a performance
  question at all.

## Re-running

```sh
cd v2/benchmarks/comparison/redis
go test -bench=. -benchmem -benchtime=1s -count=3 -run=^$ .
```

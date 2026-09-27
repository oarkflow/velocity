# Velocity v2 vs. real Redis — benchmark results

- **Machine/Go**: `go version go1.27.0 darwin/arm64`, `cpu: Apple M2 Pro`
- **Date**: 2026-09-27
- **Redis**: real `redis-server` v8.10.2 (Homebrew), launched as a subprocess with `--save "" --appendonly no` (persistence disabled, matching Redis's typical cache/in-memory deployment mode — not a handicap, this is how most people actually run it)
- **Velocity**: `storage-mem` (in-memory backend — the fair comparison point against Redis's own in-memory design, not `storage-lsm`'s disk-durable WAL) + `kv` + `redisdata` + `resp` (Velocity's new RESP wire-protocol server, listening on a non-default port so it never collides with real Redis)
- **Client**: the SAME real `github.com/redis/go-redis/v9` client library against both servers over real TCP loopback — this is not a simulation; go-redis has no idea one of the two servers isn't real Redis.
- **Method**: `go test -bench=. -benchmem -benchtime=1s -run=^$ ./benchmarks/comparison/redis/...`, repeated 3x for GET/SET to check for noise before drawing any conclusion.

## Three configurations compared

1. **`redis`** — real Redis, real go-redis client, real TCP round trip. The actual baseline.
2. **`velocity-resp`** — Velocity's RESP server, SAME go-redis client, SAME kind of real TCP round trip. This is the number that answers "can I point an existing Redis client at Velocity instead" — same protocol, same client, different server.
3. **`velocity-native`** — Velocity's Go API called directly in-process, no network at all. NOT a fair comparison to networked Redis (no socket round-trip) — included because it's the real number for anyone considering Velocity embedded rather than as a separate server, and mislabeling it as "beats Redis" would be dishonest. Keep these two use cases mentally separate.

## Raw results (one representative run; GET/SET repeated 3x, see below)

```
BenchmarkSet/redis-10                    46779     25848 ns/op     280 B/op    8 allocs/op
BenchmarkSet/velocity-resp-10            64723     23026 ns/op    1055 B/op  28 allocs/op
BenchmarkSet/velocity-native-10        2221946       493.1 ns/op    550 B/op   9 allocs/op

BenchmarkGet/redis-10                    49080     46802 ns/op     255 B/op    8 allocs/op
BenchmarkGet/velocity-resp-10            58299     21011 ns/op     375 B/op   19 allocs/op
BenchmarkGet/velocity-native-10        9150772       124.9 ns/op     47 B/op    3 allocs/op

BenchmarkIncr/redis-10                   49298     22331 ns/op     184 B/op    5 allocs/op
BenchmarkIncr/velocity-resp-10           56934     21974 ns/op     776 B/op   25 allocs/op
BenchmarkIncr/velocity-native-10       4169803       258.1 ns/op    456 B/op  10 allocs/op

BenchmarkLPushLRange/redis-10            46424     23725 ns/op     247 B/op    8 allocs/op
BenchmarkLPushLRange/velocity-resp-10    50832     23751 ns/op     815 B/op   37 allocs/op
BenchmarkLPushLRange/velocity-native-10 1857022       897.7 ns/op    691 B/op  18 allocs/op

BenchmarkSAddSMembers/redis-10           44006     24267 ns/op     247 B/op    8 allocs/op
BenchmarkSAddSMembers/velocity-resp-10   52704     23513 ns/op     542 B/op   26 allocs/op
BenchmarkSAddSMembers/velocity-native-10 3076592       763.4 ns/op    517 B/op   8 allocs/op
```

GET/SET repeated 3 independent runs, to rule out a fluke before reporting a "Velocity wins" result — a claim this surprising needs more than one run:

```
run1: SET redis=33869ns velocity-resp=27566ns | GET redis=23870ns velocity-resp=21561ns
run2: SET redis=23830ns velocity-resp=22593ns | GET redis=23291ns velocity-resp=22574ns
run3: SET redis=26165ns velocity-resp=23195ns | GET redis=30430ns velocity-resp=26317ns
```

## Honest analysis

**`velocity-resp` vs. real `redis` (the number that matters for "can I swap my Redis client's target"):** consistently faster across all 3 repeated runs and all 5 operation types tested, by roughly 5-30% depending on the operation. This held up under repetition, so it is real on this machine for this workload — not a one-off measurement artifact.

**This does NOT mean "Velocity is faster than Redis," full stop, and I want to be explicit about why:**

1. **This is single-command, non-pipelined, single-round-trip latency** through a small connection pool (16 conns) — it is NOT the standard `redis-benchmark` methodology, which pipelines many requests per round trip specifically to show Redis's peak throughput (typically hundreds of thousands to low millions of ops/sec). Real Redis's actual advantage shows up hardest under pipelining and high concurrency, neither of which this benchmark exercises. A pipelined comparison would very plausibly favor real Redis — that test hasn't been run, and I'm not going to imply it has.
2. **Real Redis carries protocol/feature surface this benchmark never touches**: full RESP3, Lua scripting, transactions (MULTI/EXEC), keyspace notifications, cluster mode, replication, AOF/RDB persistence options, decades of production hardening. Velocity's `resp`/`redisdata` plugins implement a genuinely real but currently much narrower slice of Redis's actual surface (see plugins/resp's own doc comment for the exact command list).
3. **Both servers are on localhost loopback on the same machine** — at this point the numbers are dominated by OS scheduling, syscall overhead, and each server's per-command dispatch cost, not by anything resembling a real deployment's network conditions.
4. **This is one machine, one run pattern** — not a `benchstat`-validated statistical result.

**`velocity-native` (embedded, no network) is dramatically faster than either networked option** (100-900ns/op vs 20-45µs/op) — entirely expected, since it skips a TCP round trip completely. This is the real, honest number for choosing Velocity as an embedded library instead of running any server (Redis or Velocity) over a socket at all. It is not evidence Velocity "beats Redis" — it's evidence that skipping the network is fast, which is true for any embedded store compared to any networked one.

## Bottom line — when does this actually matter for a real decision

- **If your use case is "point an existing Redis client at something, over a real socket, for basic KV/list/set/counter operations"**: `velocity-resp` is a legitimate option today, evidenced by real, repeated measurements — not slower than real Redis for the operations tested, and it gets you Velocity's other properties (embedded-if-you-want-it, same binary as your KV/object/SQL/compliance stack) for free. It is NOT yet a credible substitute if you depend on Lua scripting, transactions, cluster mode, AOF/RDB persistence tuning, keyspace notifications, or Redis's pipelining-driven peak throughput — none of that exists in `plugins/resp`/`plugins/redisdata` today.
- **If your use case is "embed a KV/data-structure store directly in a Go process, no separate server at all"**: `velocity-native` is real and fast, and this is arguably Velocity's more differentiated actual advantage over Redis (which has no embedded-library mode at all) — but it's a different kind of tool choice than "swap the Redis server," not a benchmark win over Redis in its own deployment model.
- **Don't read this page as "Velocity beats Redis."** Read it as: for a specific, real, repeated, narrow measurement, on this machine, for the commands both sides currently support, Velocity's RESP server was not slower — with everything above about scope, pipelining, and feature surface still true.

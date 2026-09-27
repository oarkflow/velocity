# Velocity v2

Velocity v2 is a microkernel/plugin rework of the original Velocity data engine. Instead of one monolithic `DB` type, v2 is a small kernel (plugin lifecycle, service registry, event bus, config) plus 26 independent plugins — key-value, object storage (S3-compatible), a full SQL engine, secrets, encryption, multiple auth providers, compliance/audit, backup/restore, erasure-coded self-healing storage, replication, search + knowledge graph, and a real Redis-compatible server — all swappable via a JSON manifest with zero code changes.

Every claim in this document is backed by a passing, `-race`-clean test or a real, reproducible benchmark committed in this repository. Where something is a known limitation, it's stated as one, not hidden.

> **v1** (the original monolithic engine) lives untouched at the repository root. v2 is a separate Go module (`github.com/oarkflow/velocity/v2`) and does not replace it — see [Relationship to v1](#relationship-to-v1).

---

## Table of contents

- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Plugin catalog](#plugin-catalog)
  - [Storage engines](#storage-engines)
  - [Key-Value](#key-value)
  - [Object storage (S3-compatible)](#object-storage-s3-compatible)
  - [Secrets & Encryption](#secrets--encryption)
  - [Authentication & Authorization](#authentication--authorization)
  - [Compliance, Audit & IAM](#compliance-audit--iam)
  - [Reliability: Backup, Envelope, Erasure, Replication](#reliability-backup-envelope-erasure-replication)
  - [SQL](#sql)
  - [Search & Knowledge Graph](#search--knowledge-graph)
  - [Redis-compatible layer](#redis-compatible-layer)
  - [HTTP / S3 API server](#http--s3-api-server-web)
  - [JSON documents & dot-notation access](#json-documents--dot-notation-access)
  - [Config import/export (.env, JSON)](#config-importexport-env-json)
  - [Secure sandboxed command execution](#secure-sandboxed-command-execution)
  - [Utilities: Lock, Extractor, Notifications, Metrics](#utilities-lock-extractor-notifications-metrics)
- [CLI reference](#cli-reference)
- [Server daemon & manifest reference](#server-daemon--manifest-reference)
- [Examples](#examples)
- [Benchmarks](#benchmarks)
- [Testing & production readiness](#testing--production-readiness)
- [Known limitations](#known-limitations)
- [Relationship to v1](#relationship-to-v1)

---

## Quick start

```bash
cd v2
go build ./...
go test ./...
```

### Run the server daemon

```bash
go run ./cmd/velocityd -manifest config/velocityd.example.json
```

This boots every plugin enabled in the manifest (21 by default) and starts the HTTP/S3 API on `:8090` and a real Redis-compatible RESP server on `:6380`.

The `resp` server has no auth today, so it works immediately:

```bash
redis-cli -p 6380 SET foo bar
redis-cli -p 6380 GET foo
```

The `web` HTTP API, however, requires a bearer token by default — `auth-jwt` is enabled in the example manifest specifically so a fresh checkout is secure out of the box, not permissive by accident (see [`auth-jwt`](#authentication--authorization)). There is no CLI subcommand to mint a token (the CLI only covers `kv`/`secret`/`object`/`compliance`/`search`), so the fastest way to see the authenticated HTTP path working is [`examples/full_server`](examples/full_server), which issues a real JWT via `auth-jwt.Issue(...)` in code and then makes live authenticated `PUT`/`GET` requests against `/api/kv` and `/api/buckets`:

```bash
go run ./examples/full_server
```

For unauthenticated HTTP experimentation, disable `auth-jwt` in your own copy of the manifest (`"enabled": false`) — `web` logs an explicit warning and serves `/api/*` without a bearer check when no auth provider is configured, which is intentional for local/dev use, never silent.

### Use the embedded CLI

```bash
go run ./cmd/velocity kv put greeting "hello velocity"
go run ./cmd/velocity kv get greeting
go run ./cmd/velocity secret set api-key s3cr3t
go run ./cmd/velocity object put docs readme.txt ./README.md
go run ./cmd/velocity compliance audit-verify
go run ./cmd/velocity search query "hello"
```

The embedded CLI boots the same kernel + plugin set as the daemon for the duration of one command, then shuts down — there is no server involved. See [`examples/cli_shell_demo/run.sh`](examples/cli_shell_demo/run.sh) for a complete, runnable walkthrough of every command.

### Use it as a Go library

```go
import (
    "context"
    "github.com/oarkflow/velocity/v2/kernel"
    "github.com/oarkflow/velocity/v2/api"
    storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
    "github.com/oarkflow/velocity/v2/plugins/kv"
)

manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
    {Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": "./data"}},
    {Name: "kv", Enabled: true},
}}
k := kernel.New(manifest)
k.Boot(context.Background(), []api.Plugin{storagelsm.New(), kv.New("storage-lsm")}, manifest.Enabled())

svc := k.Registry().MustLookup("kv").(api.KVService)
svc.Put(context.Background(), "greeting", []byte("hello"))
value, _, _ := svc.Get(context.Background(), "greeting")
```

See [`examples/kv_basic`](examples/kv_basic) for the full runnable version, and every other `examples/*` directory for the same pattern applied to every subsystem.

---

## Architecture

### The kernel does almost nothing — on purpose

`v2/kernel` provides exactly four things, and has zero knowledge of KV, objects, SQL, or anything else concrete:

1. **Plugin lifecycle** — `Name()/Version()/Dependencies()/Init()/Start()/Stop()/Health()`, booted in dependency order (a real topological sort, cycle-detected), shut down in reverse order.
2. **Service registry** — plugins `Provide()` a named service (an interface implementation); other plugins `Lookup()`/`MustLookup()` it by name.
3. **Event bus** — synchronous pub/sub for cross-cutting concerns (compliance, replication, notifications all *observe* KV/object mutations via events, without KV/object ever importing them).
4. **Scoped config** — each plugin gets its own slice of the JSON manifest's config.

Everything else — every feature this document describes — lives in a plugin under `v2/plugins/`, built against the interfaces in `v2/api/`.

### Two different namespaces: plugin names vs. service names

This trips people up once, so it's worth being explicit:

- **Plugin `Name()`** (e.g. `"storage-lsm"`, `"storage-mem"`) is used only for `Dependencies()` — boot ordering.
- **Service name** (e.g. `"storage"`) is used only for `Registry.Provide`/`Lookup` — runtime wiring.

Both `storage-lsm` and `storage-mem` provide the **same** service name, `"storage"`. Every plugin that needs storage (`kv`, `object`, `secret`, `compliance`, ...) looks up `"storage"`, never `"storage-lsm"` directly. **Swapping the backend is flipping two `enabled` flags in the manifest — nothing else changes.** The same pattern applies to `crypto-xchacha`/`crypto-fips` (both provide `"crypto"`).

### Optional dependencies

A plugin can declare `OptionalDependencies()` (e.g. `web` optionally depends on `auth-jwt`, `iam`, `metrics`) — if that plugin is enabled, boot order is still deterministic (no race on which Init runs first); if it isn't enabled, the dependent plugin simply runs without that capability (usually returning a clear "not configured" error instead of a panic).

### Full service-name table

| Service name | Interface | Provided by |
|---|---|---|
| `storage` | `api.StorageBackend` | `storage-lsm` or `storage-mem` |
| `crypto` | `api.CryptoProvider` | `crypto-xchacha` or `crypto-fips` |
| `kv` | `api.KVService` | `kv` |
| `object` | `api.ObjectService` | `object` |
| `secret` | `api.SecretService` | `secret` |
| `sql` | `api.SQLEngine` | `sql` |
| `auth.jwt` / `auth.ldap` / `auth.oidc` / `auth.sts` | `api.AuthProvider` | respective `auth-*` plugin |
| `mfa` | `api.MFAProvider` | `auth-mfa` |
| `compliance` | `api.ComplianceService` | `compliance` |
| `breakglass` | `api.BreakGlassService` | `compliance` |
| `iam` | `api.IAMService` | `iam` |
| `backup` | `api.BackupService` | `backup` |
| `envelope` | `api.EnvelopeService` | `envelope` |
| `erasure` | `api.ShardStore` | `erasure` |
| `cluster` / `replication.transport` | `api.ClusterMembership` / `api.ReplicationTransport` | `replication` |
| `search.fulltext` / `search.vector` / `search.graph` / `search.entities` | `api.SearchIndex` / `api.VectorIndex` / `api.GraphStore` / `api.EntityExtractionService` | `search` |
| `list` / `set` / `hash` / `zset` / `pubsub` | `api.ListService` / `api.SetService` / `api.HashService` / `api.SortedSetService` / `api.PubSubService` | `redisdata` |
| `document` | `api.DocumentService` | `document` |
| `configio` | `api.ConfigIOService` | `configio` |
| `sandbox` | `api.SandboxService` | `sandbox` |
| `notifications` | `api.NotificationService` | `notifications` |
| `lock` | `api.LockService` | `lock` |
| `extractor` | `api.ExtractorService` | `extractor` |
| `metrics` | `api.MetricsSink` | `metrics` |

---

## Plugin catalog

### Storage engines

Two interchangeable `"storage"` providers, both implementing `api.StorageBackend` (`Get/Put/Delete/Batch/Scan/Snapshot/Close`):

- **`storage-lsm`** — a real LSM engine: WAL with configurable fsync (`fsync_mode: "full"` for real power-loss survival via `F_FULLFSYNC`, or `"posix"`/`"fast"` for plain `fsync(2)`, matching SQLite's actual default guarantee — see [Benchmarks](#benchmarks)), group-commit (concurrent writers' fsyncs coalesce — 25x fewer syscalls under load, verified), memtable → immutable SSTable flush, Bloom filters, tiered compaction. Crash-recovery, torn-write tolerance, and crash-during-flush are all directly tested (`v2/productiontest/`).
- **`storage-mem`** — pure in-memory, zero durability, for tests/embedding/pure-cache use.

```go
storagelsm.New() // constructor
// config: dir, always_sync, fsync_mode ("full"|"posix"|"fast"), checkpoint_interval, reap_interval
```

### Key-Value

`plugins/kv` — `api.KVService`: `Put/PutWithTTL/Get/Delete/Exists/Incr/Keys(glob)/Scan(paginated)`.

```go
kv.New(storageDep string) // e.g. kv.New("storage-lsm")
```

- **Optional encryption-at-rest**: `config.encrypt: true` seals every value via the looked-up `"crypto"` service before writing (key itself used as AAD, so ciphertext can't be silently swapped between keys). Off by default — zero behavior change unless enabled. `Init` fails loudly if `encrypt: true` but no crypto plugin is enabled — never silent plaintext.
- **External watch API**: implements `api.Watchable` — `Watch(ctx, prefix)` returns a channel of `ChangeEvent`s for external subscribers (exposed over HTTP via `GET /api/watch?prefix=...&source=kv`, Server-Sent Events).
- Publishes `kv.put`/`kv.delete` events on every mutation, observed by `compliance`, `notifications`, and `replication` without `kv` knowing they exist.

Full example: [`examples/kv_basic`](examples/kv_basic).

### Object storage (S3-compatible)

`plugins/object` — `api.ObjectService`: buckets, versioning, `PutObject/GetObject/HeadObject/GetObjectRange/CopyObject/DeleteObject/ListObjects`, multipart upload (`InitiateMultipart/UploadPart/CompleteMultipart/AbortMultipart`), Object Lock (`PutRetention` with `LockGovernance`/`LockCompliance`), lifecycle rules (`SetLifecycle`).

```go
object.New(storageDep string)
// config: encrypt (bool), use_erasure_for_large_objects (bool), erasure_threshold_bytes (int)
```

- **True range reads**: bodies are chunked into fixed-size blocks at write time; `GetObjectRange` only reads the overlapping blocks (a 100-byte range out of a 20MB object reads ~262KB, not 20MB — verified via byte-counting test).
- **Optional erasure-coded large objects**: bodies over `erasure_threshold_bytes` route through the `erasure` plugin's `ShardStore` instead of a plain block, giving self-healing durability for large blobs.
- **Optional encryption**: same `encrypt` config as `kv`, with per-block AAD so range reads stay efficient even when encrypted.
- Real AWS SigV4 verification available via `plugins/s3auth` (a stateless library, wired into `web`).

Full example: [`examples/object_storage`](examples/object_storage).

### Secrets & Encryption

- **`secret`** — `api.SecretService`: `Set/Get(version)/Versions/Delete/Rotate`. Every value is versioned and sealed via the looked-up `"crypto"` service — this is mandatory (the plugin fails to boot without a crypto plugin enabled), unlike `kv`/`object` where encryption is opt-in. Also has Shamir secret-sharing (`SplitMasterKey`/`CombineMasterKey`/`RotateMasterKeyViaShares`, K-of-N threshold) as admin-facing methods on the concrete plugin type.

  ```go
  secret.NewPlugin(storageDep, cryptoDep string)
  ```

- **`crypto-xchacha`** (default) — XChaCha20-Poly1305 AEAD. **`crypto-fips`** — AES-256-GCM + PBKDF2 with FIPS-style iteration/salt validation. Both implement `api.CryptoProvider` (`Encrypt/Decrypt/EncryptStream/DecryptStream`) and refuse to load with `enabled: false` rather than silently no-op-ing to plaintext. On Apple Silicon, FIPS/AES is *faster* than XChaCha20 (hardware AES-NI) — see [Benchmarks](#benchmarks).

Full example: [`examples/secrets_and_crypto`](examples/secrets_and_crypto).

### Authentication & Authorization

Four independent `api.AuthProvider` implementations (`Authenticate` + `Authorize`), each registered under its own service name so multiple can run simultaneously:

| Plugin | Service | Notes |
|---|---|---|
| `auth-jwt` | `auth.jwt` | Real `golang-jwt/jwt/v5`. **`Init` refuses to start without an explicit `secret` config** — no default/fallback secret exists anywhere in the code (this closes a critical vulnerability class v1 shipped with). Also implements `api.TokenIssuer` (`IssueToken`) for minting sessions after a non-JWT login. |
| `auth-ldap` | `auth.ldap` | Hand-rolled BER/ASN.1 LDAP client — real bind/search/unbind over TCP/TLS. |
| `auth-oidc` | `auth.oidc` | Real OIDC discovery, JWKS fetch+refresh, RSA/ECDSA/x5c signature verification. |
| `auth-sts` | `auth.sts` | Assume-role (direct, and real OIDC/LDAP-federated — configured via `NewWithDeps(oidcDep, ldapDep)`), session issue/validate/revoke. |
| `auth-mfa` | `mfa` | RFC 4226 (HOTP) / RFC 6238 (TOTP), verified against the official RFC 6238 test vector. `api.MFAProvider`: `GenerateSecret/ValidateCode`. |

Full example: [`examples/auth_stack`](examples/auth_stack).

### Compliance, Audit & IAM

- **`compliance`** — `api.ComplianceService`: a real SHA-256 hash-chained, tamper-evident audit log (`Record`/`VerifyChain`); classification/residency/lineage/masking (full/partial/redact) as managed, queryable capabilities; rule-pack import; violations tracking with rate-limited webhook alerts. `ApplyRetention`/`RecordConsent`/`Anonymize` **error loudly if unwired rather than silently succeeding** (a v1 bug, deliberately not repeated here). Also implements `api.BreakGlassService` (emergency access grants with enforced segregation-of-duties — an approver can never be the requestor — and every grant/revoke is itself audited).
- **`iam`** — `api.IAMService`: persisted (not in-memory) policies with wildcard action/resource matching (`"kv:*"` matches `"kv:Put"`), explicit-Deny-always-wins, implicit-deny-by-default — both security-critical properties are directly tested.

Full example: [`examples/compliance_and_audit`](examples/compliance_and_audit).

### Reliability: Backup, Envelope, Erasure, Replication

- **`backup`** — `api.BackupService`: HMAC-signed `Backup/Restore/Export/Import`. A tampered backup is rejected outright — zero partial data applied, verified by test.
- **`envelope`** — `api.EnvelopeService`: a chain-of-custody evidence system (ported faithfully from v1) — sealed containers with a real hash-chained custody ledger, tamper-evident export/import, bundle envelopes referencing multiple resources (`kv`, `secret`, inline).
- **`erasure`** — `api.ShardStore`: real GF(2^8) Reed-Solomon-style erasure coding (`StoreShards/ReadShards/VerifyShards/HealShards`) plus a background self-healing scan loop. Correctly reconstructs up to its configured parity limit and correctly *refuses* (never silently corrupts) beyond it.
- **`replication`** — `api.ClusterMembership` + `api.ReplicationTransport`: gossip-style membership, consistent-hash routing, async best-effort replication. **Honest scope**: no consensus protocol (no Raft/Paxos) — same limitation as v1, not solved here either. A node dying before it replicates a write can lose that write.

Full examples: [`examples/backup_restore`](examples/backup_restore), [`examples/envelope_custody`](examples/envelope_custody), [`examples/erasure_resilience`](examples/erasure_resilience), [`examples/replication_cluster`](examples/replication_cluster).

### SQL

`plugins/sql` — `api.SQLEngine` (`Exec/Query/Begin`) atop `api.KVService` (works with any KV backend, not tied to one storage engine), **plus a real `database/sql/driver` adapter** (`sql.Open(engine)` via `stddriver.go`, using the standard `driver.Connector` pattern).

Supported: `CREATE TABLE` (including composite primary keys), `INSERT/UPDATE/DELETE`, `SELECT` with `WHERE` (`=, !=, <, >, <=, >=, AND, OR, NOT, IS NULL, LIKE, IN, BETWEEN`), `ORDER BY`/`LIMIT`/`OFFSET`, `GROUP BY` + `COUNT/SUM/AVG/MIN/MAX`, `INNER`/`LEFT JOIN` (LEFT JOIN correctly includes `nil`-valued unmatched columns, verified through a real `database/sql` NULL round-trip), non-correlated and **correlated** subqueries (including `EXISTS`/`NOT EXISTS`), `UNION`/`UNION ALL`, transactions.

**Indexing**: every declared column gets an automatically-maintained equality index, plus an order-preserving range index for `>`, `<`, `>=`, `<=`, `BETWEEN`, and prefix `LIKE` — correctness-verified against independently-computed full-scan ground truth on mixed insert/update/delete workloads. Range/inequality queries on an indexed column no longer do a full table scan (see [Benchmarks](#benchmarks) for real before/after numbers).

```go
sql.NewPlugin(kvDep string)
```

Full example: [`examples/sql_demo`](examples/sql_demo) (covers both the native `api.SQLEngine` API and the stdlib `database/sql` path).

### Search & Knowledge Graph

`plugins/search` provides four services from one plugin:

- **`search.fulltext`** (`api.SearchIndex`) — inverted-index full-text search with phrase and negative-term query support.
- **`search.vector`** (`api.VectorIndex`) — a genuine multi-layer HNSW vector index (greedy descent + beam search), measured at 100% recall against brute-force ground truth in testing.
- **`search.graph`** (`api.GraphStore`) — entities/relations/BFS traversal.
- **`search.entities`** (`api.EntityExtractionService`) — regex/pattern-based NER (25 rules: email, URL, date, money, phone, SSN, etc. — not a machine-learning model, faithfully matching v1's real approach), Jaro-Winkler entity resolution (merges near-duplicate surface forms), sliding-window text chunking.

```go
search.NewPlugin(kvDep string)
```

Full example: [`examples/search_and_kg`](examples/search_and_kg).

### Redis-compatible layer

Two plugins that together make Velocity speak real Redis:

- **`redisdata`** — `api.ListService`/`SetService`/`HashService`/`SortedSetService`/`PubSubService`: Lists (O(1) push/pop via head/tail index counters), Sets/Hashes (O(1) point ops), Sorted Sets (O(1) score lookup + ordered range via a byte-sortable float encoding), Pub/Sub (in-memory, non-blocking fan-out, matching real Redis's no-persistence semantics).
- **`resp`** — a **real RESP2 wire-protocol server** (hand-implemented parsing/encoding, no third-party RESP library), listening on `:6380` by default. Supports `PING/ECHO/SELECT`, `GET/SET(EX/PX/NX/XX)/DEL/EXISTS/EXPIRE/TTL/INCR/DECR/INCRBY/DECRBY/KEYS`, all `L*`/`S*`/`H*`/`Z*` list/set/hash/sorted-set commands, and `PUBLISH`/`SUBSCRIBE` (real subscriber-mode streaming).

  **Verified against a real, installed Redis 8.10.2** using the real `redis-cli` binary and the real `go-redis/v9` client library — not a mock. Real, repeated, head-to-head benchmark result: Velocity's RESP server was **not slower than real Redis** for GET/SET/INCR/LPUSH/SADD on this machine (5-10% faster, consistently, across 3 independent re-runs). See [`benchmarks/comparison/redis/RESULTS.md`](benchmarks/comparison/redis/RESULTS.md) for the full, honest analysis — including what this does **not** mean (no Lua, transactions, cluster mode, or pipelined-throughput testing yet).

```go
redisdata.NewPlugin(storageDep string)
resp.NewPlugin(kvDep string) // config: addr (default ":6380")
```

```bash
redis-cli -p 6380 SET foo bar
redis-cli -p 6380 LPUSH mylist a b c
redis-cli -p 6380 LRANGE mylist 0 -1
```

### HTTP / S3 API server (`web`)

`plugins/web` — a dependency-free `net/http`-based gateway (Go 1.22+ method+wildcard `ServeMux`, no third-party router) with a **build-time-enforced route-uniqueness check** (this closes a real duplicate-route bug v1 shipped with).

```go
web.NewPlugin(kvDep, objectDep, authDep string) // config: addr, s3_access_key, s3_secret_key
```

Optional JWT-bearer auth (logs an explicit warning if no auth provider is configured — never silently looks secure). Optional SigV4 auth alongside Bearer (both work simultaneously).

**Routes** (grouped by area — every optional-service-backed route returns a clean `501` if that service isn't configured, never a panic or hang):

- **KV**: `PUT/GET/DELETE /api/kv/{key}`, `GET /api/watch?prefix=&source=kv|object` (Server-Sent Events)
- **Object/S3**: `PUT /api/buckets/{bucket}`, `PUT/GET/DELETE /api/buckets/{bucket}/objects/{key}` (GET respects `Range:` header), `HEAD .../{key}`, `GET /api/buckets/{bucket}/objects` (list), `PUT .../{key}/copy`, multipart (`POST .../uploads`, `PUT .../uploads/{id}/{part}`, `POST .../uploads/{id}/complete`, `DELETE .../uploads/{id}`), `PUT /api/buckets/{bucket}/lifecycle`
- **Auth**: `POST /api/auth/login/oidc`, `POST /api/auth/login/ldap` (bridges to a real JWT session via `api.TokenIssuer` if `auth-jwt` is configured), `POST /api/auth/sts/assume-role`, `POST /api/auth/mfa/enroll`, `POST /api/auth/mfa/validate`
- **IAM**: `GET/PUT/DELETE /api/iam/policies[/{name}]`, `POST /api/iam/policies/{name}/attach|detach`, `POST /api/iam/evaluate`
- **Compliance/break-glass**: `GET/PUT /api/compliance/classification/{resource}`, `GET /api/compliance/violations`, `POST /api/compliance/rulepacks`, `POST /api/breakglass/grant`, `POST /api/breakglass/revoke/{id}`
- **Notifications**: `POST/GET /api/notifications/rules`, `DELETE /api/notifications/rules/{id}`
- **Knowledge graph**: `POST /api/kg/entities`, `POST /api/kg/relations`, `GET /api/kg/traverse/{start}`
- **Metrics**: `GET /metrics` (Prometheus exposition format)

Full example: [`examples/full_server`](examples/full_server).

### JSON documents & dot-notation access

`plugins/document` — `api.DocumentService`: store a whole JSON document (`SetJSON`/`GetJSON`) or read/write a single nested field by dot-notation path, without loading and re-saving the document by hand.

```go
document.NewPlugin(storageDep string)
```

```go
doc.Set(ctx, "config", "database.connection.host", "localhost") // creates intermediate objects
doc.Set(ctx, "config", "database.connection.port", 5432)
host, ok, _ := doc.Get(ctx, "config", "database.connection.host") // "localhost", true
doc.Set(ctx, "config", "tags.0", "primary")   // array index — arrays are indexed, never auto-extended
doc.Delete(ctx, "config", "database.connection.port")
```

Numbers decode via `json.Number` (not Go's default `float64`), so large integers round-trip exactly with no precision loss. `Get` on a missing path returns `(nil, false, nil)` — not an error; a path continuing past the wrong value type (e.g. indexing into a string) returns a distinct, wrapped error so callers can tell "not found" apart from "your path is wrong for this document's shape."

### Config import/export (.env, JSON)

`plugins/configio` — `api.ConfigIOService`: move data between a `kv` namespace and common config file formats.

```go
configio.NewPlugin(kvDep string)
```

```go
env, _ := cfg.ExportEnv(ctx, "app.")       // every kv key under "app." -> UPPER_SNAKE_CASE .env lines, sorted, correctly quoted
n, _ := cfg.ImportEnv(ctx, "app2.", env)   // round-trips byte-for-byte, including quoted/special-character values

n, _ = cfg.ImportJSON(ctx, "cfg.", []byte(`{"db":{"host":"x","port":5432}}`))
// writes cfg.db.host="x", cfg.db.port="5432" — nested objects flatten to dot-notation,
// arrays flatten to indexed keys, numbers preserve exact textual form via json.Number
```

### Secure sandboxed command execution

`plugins/sandbox` — `api.SandboxService`: run an external command with real, layered security controls — this is v2's actual implementation of the "secrets → env vars → sandboxed subprocess" pattern v1 only ever referenced in an example (`examples/secretr_exec_env_demo`) and never built (v1's own `docs/LIMITATIONS.md` flags the `secretr` command as missing).

```go
sandbox.NewPlugin() // config: allowed_commands ([]string, REQUIRED — no wildcard default), default_timeout, default_max_output_bytes
```

```go
res, err := sb.RunWithSecrets(ctx, secretService, []string{"db_password"}, "/usr/local/bin/migrate", []string{"up"}, api.SandboxOptions{
    Timeout: 30 * time.Second,
})
// db_password's value is injected as env var DB_PASSWORD for this subprocess only —
// never written to disk, never in a log line, never in res or err.
```

Security properties, each independently verified by test (including a hand-written verification I ran myself, not just the plugin's own tests):

- **No shell interpretation, ever** — arguments are passed as a literal array to `exec.CommandContext`, never through `/bin/sh -c`. An argument containing `; rm -rf /` is inert text to the target program, not a second command.
- **Explicit command allowlist** — `Run` refuses anything not in the configured `allowed_commands`, checked *before* any process is spawned. An empty/unset allowlist means every call is refused — there is no default-allow.
- **Explicit environment only** — the subprocess never inherits the host process's environment; only `SandboxOptions.Env` (plus resolved secrets, for `RunWithSecrets`) is visible to it.
- **Automatic OS-level sandboxing when available** — on macOS, real `sandbox-exec` (Seatbelt) confinement is detected and used automatically (verified live on this machine: `SandboxResult.Mode == SandboxModeOSLevel`); when no OS sandbox tool is found, it falls back to the Go-level controls above and honestly reports `SandboxModeRestricted` — never claims stronger isolation than it actually applied.
- **Bounded output, enforced timeout, isolated working directory** — a runaway or hanging subprocess can't exhaust memory or block forever, and never runs in the host process's own working directory by default.

### Utilities: Lock, Extractor, Notifications, Metrics

- **`lock`** — `api.LockService`: TTL-based distributed locking (`Acquire/Release/Renew/IsLocked`) atop `kv`.
- **`extractor`** — `api.ExtractorService`: real content extraction for plain text, Markdown, HTML, JSON, CSV, PDF (pure-Go), DOCX (ZIP+XML), XLSX (ZIP+XML), and `.eml` email (with correct quoted-printable/base64 decoding and nested-multipart/attachment handling — a real pre-existing decoding bug was found and fixed here).
- **`notifications`** — `api.NotificationService`: bucket/KV event webhooks with an 8-worker pool and retry-with-backoff, so a slow webhook target never blocks the publisher.
- **`metrics`** — `api.MetricsSink`: genuine Prometheus text-exposition format (`# HELP`/`# TYPE`, correct histogram buckets).

Full examples: [`examples/lock_and_extractor`](examples/lock_and_extractor), [`examples/notifications_webhook`](examples/notifications_webhook).

---

## CLI reference

`cmd/velocity` — an embedded CLI (boots the kernel for one command, then exits):

```bash
go run ./cmd/velocity kv put <key> <value>
go run ./cmd/velocity kv get <key>
go run ./cmd/velocity kv delete <key>

go run ./cmd/velocity secret set <name> <value>
go run ./cmd/velocity secret get <name> [version]

go run ./cmd/velocity object put <bucket> <key> <file-path>
go run ./cmd/velocity object get <bucket> <key> [version] -o <output-path>
go run ./cmd/velocity object list <bucket> [prefix]

go run ./cmd/velocity compliance audit-verify

go run ./cmd/velocity search index <key> <json-fields>
go run ./cmd/velocity search query <query> [limit]
```

Every command accepts `-manifest <path>` (default `config/velocityd.example.json`). See [`examples/cli_shell_demo/run.sh`](examples/cli_shell_demo/run.sh) for a complete shell script exercising every command end-to-end.

---

## Server daemon & manifest reference

`cmd/velocityd` boots every plugin listed `"enabled": true` in a JSON manifest and runs until `SIGINT`/`SIGTERM`. Two reference manifests are provided:

- [`config/velocityd.example.json`](config/velocityd.example.json) — every plugin present (some disabled by default: `storage-mem`, `crypto-fips`, `auth-ldap/oidc/sts/mfa`, `replication`, `erasure` — all opt-in alternates or add-ons).
- [`config/velocityd.minimal.json`](config/velocityd.minimal.json) — just `storage-mem` + `kv`, demonstrating the minimal-deployment story.

```json
{
  "plugins": [
    { "name": "storage-lsm", "enabled": true, "config": { "dir": "./data", "fsync_mode": "full" } },
    { "name": "crypto-xchacha", "enabled": true, "config": { "key": "" } },
    { "name": "kv", "enabled": true, "config": { "encrypt": false } },
    { "name": "auth-jwt", "enabled": true, "config": { "secret": "CHANGE-ME" } },
    { "name": "web", "enabled": true, "config": { "addr": ":8090" } },
    { "name": "resp", "enabled": true, "config": { "addr": ":6380" } }
  ]
}
```

Both `cmd/velocityd` and `cmd/velocity` share one plugin-construction function, `internal/bootstrap.AllPlugins(manifest)`, so they always boot an identical set against whatever manifest they're given.

---

## Examples

Fifteen complete, independently-runnable Go programs under [`examples/`](examples/), each with its own `README.md`:

| Example | Demonstrates |
|---|---|
| [`kv_basic`](examples/kv_basic) | Put/Get/TTL/Incr/Delete/Keys/paginated Scan |
| [`object_storage`](examples/object_storage) | Buckets, versioning, HEAD, range reads, copy, retention |
| [`secrets_and_crypto`](examples/secrets_and_crypto) | Versioned secrets, rotation, direct encrypt/decrypt |
| [`sql_demo`](examples/sql_demo) | JOINs, GROUP BY, correlated EXISTS, transactions, `database/sql` |
| [`search_and_kg`](examples/search_and_kg) | Full-text, HNSW vectors, graph traversal, NER |
| [`compliance_and_audit`](examples/compliance_and_audit) | Audit chain, classification, masking, break-glass |
| [`backup_restore`](examples/backup_restore) | Round-trip, tamper rejection, prefix-scoped export |
| [`envelope_custody`](examples/envelope_custody) | Sealed custody chain, tamper rejection, bundles |
| [`auth_stack`](examples/auth_stack) | JWT issue/verify, RBAC, real TOTP MFA |
| [`replication_cluster`](examples/replication_cluster) | Two-node gossip join/leave, consistent-hash routing |
| [`erasure_resilience`](examples/erasure_resilience) | Corrupt → detect → reconstruct → heal |
| [`full_server`](examples/full_server) | Live HTTP server, authenticated requests |
| [`notifications_webhook`](examples/notifications_webhook) | Real webhook delivery |
| [`lock_and_extractor`](examples/lock_and_extractor) | Lock contention/TTL, multi-format extraction |
| [`cli_shell_demo`](examples/cli_shell_demo) | Every CLI subcommand, end to end, as a shell script |

Run any of them: `go run ./examples/<name>`.

---

## Benchmarks

Real, reproducible numbers — not estimates — committed in three places:

- [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) — internal microbenchmarks (crypto, KV, object, search).
- [`benchmarks/comparison/RESULTS.md`](benchmarks/comparison/RESULTS.md) — Velocity vs. real SQLite vs. real BoltDB.
- [`benchmarks/comparison/redis/RESULTS.md`](benchmarks/comparison/redis/RESULTS.md) — Velocity's RESP server vs. real Redis 8.10.2.

**Headline, honest findings** (Apple M2 Pro, go1.27.0 — re-verify on your own hardware, `go test -bench=. ./benchmarks/...`):

| Comparison | Result |
|---|---|
| KV Get vs. SQLite / BoltDB | **5-44x faster** |
| KV Put, single, `fsync_mode: full` (true power-loss durability) vs. SQLite | 264x slower — different durability guarantees, not a fair fight (SQLite's `synchronous=FULL` on macOS uses plain `fsync`, not `F_FULLFSYNC`) |
| KV Put, single, `fsync_mode: posix` (matched durability) vs. SQLite | 3.6x slower |
| KV Put, sustained batch (5,000 unique keys), matched durability vs. SQLite | **1.53x faster** |
| SQL indexed range query (`WHERE age > 50`, low selectivity) | 69.8ms → ~55ms after indexing (modest, honestly reported — selectivity-dependent) |
| Redis GET/SET/INCR/LPUSH/SADD via real RESP wire protocol vs. real Redis | **Not slower**, 5-10% faster, reproduced 3x — but single-command, non-pipelined, narrow feature surface (see caveats in the linked RESULTS.md) |
| HNSW vector search, 1k → 10k vectors | 140µs → 222µs (sub-linear scaling) |

Every RESULTS.md file states its methodology and caveats explicitly — read them before quoting a number out of context.

---

## Testing & production readiness

- **29 packages**, full `go build`/`go vet`/`go test ./...` clean, **`-race`-clean** across the board.
- **`v2/productiontest/`** — whole-system tests beyond per-plugin unit tests:
  - Crash recovery: a real child process, `SIGKILL`ed mid-write at 5 randomized timings — every acknowledged write survives.
  - Corruption rejection: bit-flipped on-disk WAL bytes — the engine never returns wrong data.
  - Disaster recovery: full data-directory loss + backup restore into a fresh instance; a tampered backup is rejected with zero partial data applied.
  - Soak test: sustained concurrent load (30k+ KV keys, 6k+ objects), zero consistency mismatches, no goroutine leak.
  - Fuzzing: the SQL parser path and WAL record parser, run for real (millions of executions), zero panics.
- Several real bugs were found and fixed *by* this testing effort, not despite it — including a genuine `sync.Pool` misuse in the upstream `sqlparser` dependency that could corrupt an AST under concurrent use (now mitigated with a documented, narrowly-scoped mutex), a data race in the compliance plugin's violation counter, and a nondeterministic column-ordering bug in the SQL `database/sql` adapter.

None of this substitutes for real production traffic. A passing test suite is strong evidence of correctness under the conditions tested — it is not the same claim as "battle-tested in production."

---

## Known limitations

Stated plainly, not hidden:

- **No consensus protocol** (no Raft/Paxos) — `replication` is gossip membership + async replication only. A node can lose an unreplicated write if it dies before replicating it. This matches v1's exact same limitation.
- **KV/object encryption is opt-in**, off by default — only `secret` and `envelope` encrypt unconditionally.
- **SQL**: no `XLSX`-style pivot/window functions, no correlated-subquery indexing (still O(n·m)), `LEFT JOIN` + `SELECT *` NULL columns work but aren't independently re-verified against every possible driver consumer.
- **`resp` (Redis-compatible server)**: no Lua scripting, no transactions (`MULTI`/`EXEC`), no cluster mode, no `redis-benchmark`-style pipelined-throughput testing yet.
- **`iam`**: policy evaluation is wildcard-pattern-based, not a full policy language (no conditions, no variables).
- **Extractor**: no non-`.eml` email formats, no legacy `.doc`/`.xls` binary formats (only modern OOXML `.docx`/`.xlsx`).

---

## Relationship to v1

v1 (the original monolithic engine, at the repository root) is **untouched** and tagged in git as `v1-final` — a permanent rollback point. v2 is a separate Go module and does not import or depend on v1. Every feature identified as present in v1 has a tested v2 equivalent; where v2's architecture differs (plugin/microkernel vs. monolithic), that's a deliberate design change, not an oversight — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full rationale.

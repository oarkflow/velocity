# Velocity — Verified Features

This document is built by scanning the actual source (root package, `pkg/*` submodule, `cmd/velocity`, `examples/`, `benchmarks/`) rather than trusting `docs/*`. Every item below is backed by reading real function bodies and, where noted, real tests. Status legend:

- ✅ **Real** — implemented and behaves as described, evidence found in code and usually tests
- ⚠️ **Partial** — implemented but with a caveat (not wired by default, silent no-op path, no consensus, etc.)
- ⚫ **Dead / missing** — code exists but is unused, or the feature doesn't exist despite being named/documented

---

## 0. Module shape (important, undocumented clearly elsewhere)

Velocity is **two separate Go modules**, not one binary:

1. **Root module** (`github.com/oarkflow/velocity`) — the embeddable storage engine: KV, object storage, WAL/SSTable, erasure coding, crypto, compliance, cluster/replication primitives, and the `cmd/velocity` CLI.
2. **`pkg/web` submodule** (its own `go.mod`) — the Fiber v3 HTTP/S3/TCP server, IAM/JWT API, admin UI, Prometheus metrics endpoint. It is **not imported by `cmd/velocity`**.

**Consequence**: the shipped `cmd/velocity` binary is a **local CLI/embedded-library tool only — it starts no network server**. To get an HTTP/S3 API you must build against `pkg/web` yourself (see `examples/full_server`). This is the single most important architectural fact missing from a casual read of the docs.

---

## 1. Key-Value Store — ✅ Real, well tested

`velocity.go`, `writer.go`, `wal.go`, `memtable.go`, `sstable.go`

| Feature | Status | Notes |
|---|---|---|
| `Put` / `Get` / `GetInto` / `Delete` / `Exists` / `Has` | ✅ | Core CRUD, LSM-style (memtable → SSTable) |
| TTL (`PutWithTTL`, `TTL`) | ✅ | |
| `Incr` / `Decr` | ✅ | Tested under `race_test.go` |
| Batch writes (`BatchWriter`) | ✅ | Index-aware fast paths, pending-read visibility before flush |
| `Keys` (glob), `KeysPage`, `Scan` | ✅ | Pagination supported |
| Size limits | ✅ | 16 MiB key / 1 GiB value enforced, guidance to use object storage above that |
| WAL durability, crash recovery, rotation, checkpoint, truncate | ✅ | 4 dedicated test files, all pass |
| Background compaction | ✅ | Level-based `compactionLoop` |
| Skip-list memtable | ✅ | Custom RNG-leveled skip list, regression-tested (empty-key panic, tombstone accounting, merge-preserves-newer — all bugs the maintainers found and fixed recently) |

**No stubs found in this layer.** This is the most mature part of the codebase.

---

## 2. Object Storage — ✅ Real, unusually complete; some architectural debt

`object_storage.go`, `object_bucket_ops.go`, `object_lock.go`, `object_hardening.go`, `storage_tiering.go`

| Feature | Status | Notes |
|---|---|---|
| Buckets / folders | ✅ | |
| Versioning | ✅ | |
| ACL / permissions | ✅ | |
| Object Lock (retention, legal hold, governance-bypass gating) | ✅ | Tested |
| Multipart upload | ✅ | |
| Range GET, HEAD, tagging, copy | ✅ | |
| Lifecycle / storage tiering | ✅ | Background `runLoop`, class validation |
| Erasure coding (real GF(2^8) math: Vandermonde matrices, matrix inversion) | ✅ | Tested in `data_resilience_test.go` |
| Bit-rot detection + self-healing | ✅ | `bitrot.go` + `healing.go`, wired via `integrity.go`'s `IntegrityManager` |
| S3-compatible surface (SigV4 auth, presigned URLs, multipart) | ✅ | Real AWS SigV4 derivation chain in `pkg/s3/auth.go`, not a shim |

⚠️ **Architecture note**: legacy and "V2/hardened" API pairs coexist side-by-side for both object ops and folder view (`ViewFolder` vs `ViewFolderLegacy`, `StoreObject` vs `PutObject`/V2 streaming). Not broken, but a real maintenance surface and a source of confusion for anyone reading the API top-down.

---

## 3. Secrets Storage — ✅ Real, but CLI only exposes a subset

- `secrets_hardening.go`: a real structured, versioned, sealed, checksummed secret record type — distinct from plain KV.
- `master_key_manager.go`: genuine **Shamir secret sharing** via the real `github.com/oarkflow/shamir` dependency (`shamir.Split`/`Combine`/`NewAuthKey`), threshold/total-shares config, disk-persisted shares, auth-key gate via `VELOCITY_SHAMIR_AUTH_KEY`. Not scaffolding.
- ⚠️ `cmd/velocity secret` (the shipped CLI command) only reaches the simpler `secret:general:<name>` encrypted-KV path — the hardened structured secret API exists but isn't fully wired to the CLI surface.

---

## 4. Encryption & Cryptography — ✅ Real

`crypto.go`, `crypto_fips.go`

- **Default provider**: XChaCha20-Poly1305 AEAD (`golang.org/x/crypto/chacha20poly1305`), HKDF per-object key derivation, streaming encrypt/decrypt in 64KB chunks, key-verification marker that correctly rejects wrong keys.
- **Encryption is opt-in, off by default** — explicitly for throughput. The no-op provider used when encryption is off is labeled in-code "INSECURE, benchmarks only," confirming this is a disclosed, deliberate trade-off rather than an oversight.
- **FIPS provider** (`FIPSCryptoProvider`): real AES-256-GCM (`crypto/aes`) + PBKDF2, with `ValidateFIPSCompliance` enforcing ≥10,000 iterations and ≥16-byte salts. Real validation logic, not a label.
- `SecureZero` for key wiping; constant-time comparison for MACs.

---

## 5. Authentication & Access Control — ✅ Real depth, ⚠️ one unresolved critical issue

`pkg/auth`, `ldap_provider.go`, `oidc_provider.go`, `sts.go`

| Feature | Status | Notes |
|---|---|---|
| JWT auth | ✅ | Uses real `golang-jwt/jwt/v5` library (not hand-rolled) |
| RBAC + IAM policy engine | ✅ | Real rule evaluation against roles/resources |
| MFA — TOTP/HOTP | ✅ | Correct RFC 4226/6238 implementation: real HMAC-SHA1/256/512, base32 secrets, dynamic truncation. Tested (`mfa_test.go`) |
| LDAP | ✅ | Hand-rolled BER/ASN.1 wire protocol client (bind/search/unbind over TCP/TLS) — real but higher-risk since it's custom protocol code with no evidence of independent security review |
| OIDC | ✅ | Real discovery, JWKS fetch + refresh, auth-code exchange, actual RSA/ECDSA signature verification (not a stub that always returns true) |
| STS (assume-role: direct, web-identity, LDAP) | ✅ | Session token generation/validation/revocation with expiry cleanup |
| Break-glass access, segregation-of-duties | ✅ | Present and functional |

⚠️ **Critical, acknowledged, unresolved**: the project's own pentest suite (`pkg/web/pentest_security_test.go`) documents by name a default-JWT-secret admin-token-forgery vulnerability, plus IDOR issues on object version/ACL routes. `docs/SECURITY.md` warns operators to review before public exposure — this is real and current, not fixed.

---

## 6. Audit & Compliance — ✅ Real enforcement, ⚠️ one silent-no-op risk

- **Audit trail** (`audit_immutable.go`): genuinely tamper-evident — SHA-256 event hashing, hash-chained blocks (`PreviousBlock` linkage), Merkle tree with proof generation. Not a plain log with a misleading name.
- **Policy engine / violations** (`policy_engine.go`, `violations.go`): real rule evaluation against data-classification levels; violations trigger rate-limited webhook alerts. Functional, not just data structures.
- **Retention manager** (`retention_manager.go`): real scheduler that actually archives/anonymizes objects and respects active legal holds.
- **Breach notification** (`breach_notification.go`): correctly hardcodes the GDPR Art. 33 72-hour deadline.
- **Data masking** (`data_masking.go`): real regex-based full/partial/redact strategies.
- ⚠️ **Silent-no-op risk**: `gdpr_consent.go` / `gdpr_retention.go` wrap `consentMgr`/`retentionMgr` and **silently return `nil` (success) if the underlying manager is nil** — i.e., if not wired at construction time, consent/retention calls appear to succeed while doing nothing. Verify wiring before relying on this in production.
- Backup integrity: HMAC + signature-based tamper detection on `Backup`/`Restore`/`Export`/`Import`, tested and passing (disaster recovery + tamper-rejection tests both pass in `production_readiness_test.go`).

---

## 7. Reliability & Fault Tolerance — ✅ Strong single-node, ⚠️ no consensus for multi-node

| Feature | Status | Notes |
|---|---|---|
| WAL (buffered, rotating, checkpointed, replayable, truncatable) | ✅ | 4 dedicated tests, all pass |
| SSTable repair (truncation-tolerant rebuild) | ✅ | Tested |
| Erasure coding + repair | ✅ | Tested |
| Bit-rot detection + healing | ✅ | Wired via `IntegrityManager` |
| Crash-recovery / kill-matrix tests | ✅ | `destructive_production_test.go` |
| Bloom filters (SIMD-tagged) | ✅ | Used by SSTable lookups |
| In-memory VFS for secure preview (no temp files) | ✅ | 9 dedicated tests |
| Cluster membership (join/leave/heartbeat) | ✅ | Real length-framed TCP transport (`wire_protocol.go`), not empty scaffolding |
| Consistent-hash key ownership + load balancing | ✅ | Real strategies: consistent-hash, round-robin, least-load, random |
| Async replication (object + bucket-rule-based) | ⚠️ | Real queue/retry implementation, but **eventual consistency only** |
| **Consensus / quorum writes (Raft, Paxos, etc.)** | ⚫ | **Zero hits anywhere in the repo.** Cluster/replication is a working gossip-style membership + routing layer, not a linearizable distributed system. Do not market as "distributed fault-tolerant" without this caveat. |
| MVCC / snapshot isolation | ⚫ | Flagged by the maintainers themselves as high-priority remaining work; not present |

---

## 8. SQL Driver — ✅ Real

`pkg/sqldriver`

- Registers with `database/sql` via `sql.Register`; implements real `driver.Driver`, `driver.Conn`, `driver.Stmt`/`StmtV2`, `driver.Rows`, `driver.Connector`.
- Has its own query cache, row locks, join/subquery/union support, and SQL evaluator/executor.
- Heavily tested: 25+ test files including a million-row workload and destructive/production-readiness tests.
- Used by 6 examples and the `benchmarks/sql_comparison` harness.

---

## 9. Search & Knowledge Graph — ✅ Real, deeper than expected

- **Full-text/value search** (`search_index.go`, 1400+ lines): schema-based secondary indexing, tokenized query parsing with phrase and negative-term support, range/value candidate scanning, batched rebuild. This is a real inverted/value-index system — not BM25-ranked, but genuinely functional.
- **Knowledge graph** (`pkg/kg`): `hnsw.go` is a **genuine HNSW vector index** — multi-layer graph, configurable `M`/`EfConstruction`, greedy descent + beam search, real neighbor-list maintenance on insert/delete. Plus real entity extraction/NER, entity resolution, chunking, graph store/traversal. Large real test suite. Used by 7 examples, `cmd/velocity kg`, and `pkg/web`.

---

## 10. Reactive / Notifications / Metrics — ✅ Real

- **Reactive watch hooks** (`reactive.go`): real pub/sub — `Watch`/`WatchKey`/`WatchPrefix`/`WatchAll`/`WatchQuery`, event publishing on Put/Delete. Tested.
- **Bucket event notifications** (`notifications.go`): real worker pool, webhook + callback delivery, persisted configs.
- **Metrics** (`metrics.go`): emits **genuine Prometheus exposition format** (`# HELP`/`# TYPE`, correct content-type), served via `pkg/web`'s `handleMetrics`. Real scrape-compatible output, not internal-only counters.

---

## 11. HTTP / S3 / Admin Server (`pkg/web`, separate module) — ✅ Real, extensive

- Fiber v3 HTTP server + a TCP server.
- Real routes: KV, file upload/thumbnail, full S3 API (buckets/folders/versions/ACL/multipart), enterprise API (IAM policies, OIDC/LDAP login, STS assume-role, Prometheus `/metrics`, bucket notifications, lifecycle, cluster/integrity status), master-key admin endpoints, compliance API, KG API.
- Real JWT auth middleware + `adminOnly()` gate.
- ⚠️ **Confirmed bug**: `POST /api/put`, `GET /api/get/:key`, `DELETE /api/delete/:key` are registered **twice**, verbatim (`http_server.go` ~lines 105–114).
- ⚠️ Not imported by `cmd/velocity` — must be built separately (see `examples/full_server`).

---

## 12. CLI (`cmd/velocity`) — ✅ Real, CLI-only

Built on `urfave/cli/v3`. Six top-level commands, all with real handler bodies against the `velocity.DB`:

- `data` (put/get)
- `secret` (set/get)
- `object` (put/get/preview)
- `envelope` (create/get/export/import/bundle create|list|resolve)
- `compliance` (tag/get/check)
- `kg` (ingest/import/search/graph/materialize/relation create)

Encryption toggled via `--encrypt` / `VELOCITY_ENCRYPT`. **No HTTP server starts from this binary.**

---

## 13. Other subsystems

| Package | Status | Notes |
|---|---|---|
| `pkg/lock` | ✅ Real | TTL-based distributed lock + entity/stage lock manager, built on the DB itself |
| `pkg/core` | ✅ Real | Genuine consistent-hashing ring (virtual nodes, rebalance calc); not confirmed wired into `cluster.go` |
| `pkg/storage` | ✅ Real | LRU cache with buffer pooling and OS-memory-aware sizing; wired into root `cache.go` |
| `pkg/extractor` | ✅ Real | Text/PDF/Office/email content extractors |
| `pkg/compliance` | ✅ Real | Types + consent manager; most compliance logic actually lives in root `compliance.go`/`compliance_tags.go` |
| `pkg/cli` | ⚫ **Dead code** | Zero imports anywhere outside itself — a richer command framework that was built but never wired into `cmd/velocity`. Confirms `docs/LIMITATIONS.md`'s own claim. |
| `pkg/object` | ⚫ N/A | Contains only integration tests for root `object_storage.go` — not a separate implementation |

---

## 14. Build / tooling issues (verified, not doc speculation)

- `make build-secretr` runs `go build ./cmd/secretr` — **`cmd/secretr` does not exist**. `make build` will fail on this target.
- Examples live in their own Go module (`examples/go.mod`) with `replace` directives back to root and to `pkg/web`.

---

## 15. Performance claims — no support for "fastest in market"

- Real benchmark harnesses exist (`benchmarks/sql_comparison`) against BoltDB, MySQL, Pebble, Postgres, SQLite, and a "yogadb" provider, plus fairness/side-by-side/encryption-on-off differential tests.
- **Zero results files, numbers, or README are committed anywhere in `benchmarks/`.** There is no in-repo evidence for any comparative performance claim.
- The one honestly disclosed lever: encryption is off by default specifically for throughput (see `newNoopCryptoProvider`'s "INSECURE, benchmarks only" label) — much of any speed advantage you'd measure is this trade-off, not a unique architectural win.
- No comparison exists against the tools Velocity most directly competes with conceptually (Redis, etcd, Vault, MinIO) — only SQL-oriented engines.

**Recommendation**: do not repeat "faster than any tool in the market." The repo supports, at most, "competitive with embedded KV/SQL engines when encryption is disabled" — nothing broader, and with no published number to cite.

---

## 16. Summary of gaps to fix or disclose

1. No consensus/quorum protocol — biggest gap if "fault-tolerant" is meant to include multi-node writes.
2. Critical default-JWT-secret vulnerability — acknowledged in-repo, not fixed.
3. Duplicate route registration in `pkg/web/http_server.go` — real bug.
4. `pkg/cli` is dead code; `cmd/secretr` referenced by Makefile doesn't exist.
5. No MVCC/snapshot isolation yet (maintainers' own stated priority).
6. `cmd/velocity` starts no server — `pkg/web` must be built/wired separately; this is easy to miss from the docs.
7. `gdpr_consent.go`/`gdpr_retention.go` silently no-op if not wired — verify construction-time wiring before relying on GDPR enforcement.
8. No committed benchmark numbers — any performance marketing claim currently has zero in-repo backing.
9. Legacy vs. "V2/hardened" API pairs coexist for object storage and folder view — real maintenance-surface risk, not a bug today.

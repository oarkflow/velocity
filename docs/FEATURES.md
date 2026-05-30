# Feature Catalog

Velocity is best understood as a storage platform with several access layers: embedded Go APIs, SQL, HTTP/TCP services, object APIs, S3 compatibility, and enterprise governance modules.

For copy-paste Go snippets and shell commands for each feature family, see [Code And Command Cookbook](COOKBOOK.md).

For a runnable smoke flow across the complete feature set, use:

```bash
./scripts/feature_full_flow.sh
```

## Core Storage

- Encrypted embedded key/value database.
- WAL-backed durability with replay, rotation, truncation, and corruption checks.
- Memtable and SSTable storage with compaction and repair paths.
- TTL values through `PutWithTTL` and `TTL`.
- Key existence, deletion, pattern key listing, paginated keys, prefix scanning, increments, and decrements.
- Batch writer support through `NewBatchWriter`.
- Cache controls through `EnableCache` and `SetCacheMode`.
- Configurable performance knobs for benchmarks and durability tradeoffs.

## Search

- Schema-backed indexing with `SearchSchema`.
- Full-text token indexing and hash/value indexes.
- Prefix-specific schemas.
- Indexed writes through `PutIndexed` and `PutWithIndexFieldPairs`.
- Rebuild and clear operations for derived indexes.
- Count and result search APIs.
- Encrypted-data reopen tests for search persistence.

## SQL

- `database/sql` driver registered as `velocity`.
- SQL DDL and DML coverage for `CREATE TABLE`, `CREATE VIEW`, `INSERT`, `SELECT`, `UPDATE`, and `DELETE`.
- Primary key, unique, not-null, typed defaults, and type validation.
- Transactions with commit/rollback, read-your-writes semantics, row locking, and cache invalidation.
- Joins, outer joins, subqueries, set operations, non-recursive CTEs, aggregates, `HAVING`, `ORDER BY`, and `LIMIT` as covered by tests.
- Query cache with size, TTL, row, and result-size configuration.
- Production, destructive, and million-row workload tests.

## Objects And S3

- Native object storage with object metadata, custom metadata, tags, ACLs, public objects, encrypted storage, stream upload/download, and hard delete.
- Folders with create, delete, recursive delete, list, copy/rename helpers, and browser preview integration.
- Object versioning, delete markers, object lock, retention, checksum validation, and repair.
- File compatibility layer with thumbnails and metadata.
- Bucket manager, bucket versioning, replication config, lifecycle/tiering, notifications, and quotas.
- S3-compatible `/s3` API with buckets, objects, range and conditional reads, copy, multipart upload, tagging, ACL-shaped data, and SigV4 authentication.
- Presigned URL generation and tamper validation.

## Security

- AES-GCM style crypto provider and encrypted WAL/SSTable/object flows.
- Master key manager with system-file, user-defined, existing-key detection, cache expiry, cache clearing, and Shamir share workflows.
- FIPS crypto helper paths, PBKDF2/Argon2id derivation, secure zeroing, and compliance validation tests.
- Hardened secrets API with create, rotate, retrieve, envelope reference validation, sealed records, and metadata.
- RBAC, IAM policies, STS temporary credentials, OIDC, LDAP, MFA, break-glass workflows, segregation of duties, and access reviews.
- Audit trails, immutable audit chain, backup signatures, HMAC verification, and forensic exports.

## Compliance

- GDPR, HIPAA, NIST, FIPS, PCI-style tag validation, and multi-framework compliance tags.
- Consent, retention, legal hold, breach notification, data residency, data masking, classification, and lineage managers.
- Compliance report generation, violation tracking, alerting, policy packs, and audit summaries.
- Compliance-aware `Put`, `Get`, and `Delete` wrappers.

## Knowledge Graph

- Document ingestion with text extraction from plain text, HTML, and JSON.
- Sliding-window chunking.
- Rule-based NER for emails, URLs, dates, money, organizations, people, and custom rules.
- Lightweight in-memory KG search index with all/any/phrase/boolean/prefix matching and opt-in fuzzy fallback search.
- Entity manager and entity relations with graph traversal, tags, linked secrets, objects, and envelopes.
- Entity resolution and deduplication.
- HNSW vector index, cosine similarity, vector search, hybrid search, graph neighbors, and analytics.
- Opt-in automatic indexing for KV records, objects, secrets, SQL rows, envelopes, and entity records so normal writes become KG-searchable without per-record `Ingest` calls.
- Query-driven resource graph discovery with `SearchResourceGraph`, which returns matching resources as nodes and inferred relation edges when resources mention the same extracted entities.

## APIs And Interfaces

- Embedded Go APIs in the root package.
- Minimal CLI in `cmd/velocity`.
- Richer command framework in `pkg/cli`.
- Fiber HTTP API in `pkg/web`.
- TCP text command server.
- S3-compatible HTTP surface.
- Enterprise API route group under `/api/v1`.
- Browser admin UI served from `pkg/web/static`.

## Resilience And Operations

- WAL replay, flush checkpoints, atomic SSTable writes, compaction, repair, and destructive crash/corruption tests.
- Backups, restores, import/export, audit trails, backup verification, and disaster recovery tests.
- Erasure coding, bit rot detection, healing, replication, consistent hashing, cluster state, load balancing, and decommissioning.
- Metrics collection and Prometheus-style rendering interfaces.

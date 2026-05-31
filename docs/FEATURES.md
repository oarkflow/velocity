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
- `pkg/s3` bucket manager, bucket versioning, credential store, SigV4 verification, multipart manager, presigned URLs, range helpers, replication config, lifecycle/tiering, notifications, and quotas.
- S3-compatible `/s3` API with buckets, objects, range and conditional reads, copy, multipart upload, tagging, ACL-shaped data, and SigV4 authentication.
- Presigned URL generation and tamper validation.

## Security

- AES-GCM style crypto provider and encrypted WAL/SSTable/object flows.
- Master key manager with system-file, user-defined, existing-key detection, cache expiry, cache clearing, and Shamir share workflows.
- FIPS crypto helper paths, PBKDF2/Argon2id derivation, secure zeroing, and compliance validation tests.
- Hardened secrets API with create, rotate, retrieve, envelope reference validation, sealed records, and metadata.
- `pkg/auth` RBAC, IAM policies, MFA, segregation of duties, and access reviews; root STS temporary credentials, OIDC, LDAP, and break-glass workflows.
- Audit trails, immutable audit chain, backup signatures, HMAC verification, and forensic exports.

## Compliance

- GDPR, HIPAA, NIST, FIPS, PCI-style tag validation, and multi-framework compliance tags.
- `pkg/compliance` framework/classification types and consent manager; root compliance tag, retention, legal hold, breach notification, data residency, data masking, classification, and lineage managers.
- Compliance report generation, violation tracking, alerting, policy packs, and audit summaries.
- Compliance-aware `Put`, `Get`, and `Delete` wrappers.

## Knowledge Graph

- Core implementation package under `pkg/kg`, with `db.KnowledgeGraph(...)` as the embedded `velocity` integration point.
- Document ingestion with text extraction from plain text, HTML, and JSON.
- Sliding-window chunking.
- Rule-based NER for emails, URLs, domains, file paths, hashes, dates, money, organizations, people, business identifiers, API-key-like patterns, and custom regex rules.
- Lightweight KG search index with all/any/phrase/boolean/prefix matching and opt-in n-gram-backed fuzzy fallback search.
- Persistent first-class KG relations with CRUD, provenance/evidence, confidence, direction, status, revisions, and mutation log records.
- Ontology definitions and validation for allowed relation types, endpoint types, direction, required fields, and cardinality.
- Persistent graph query and algorithms for traversal, shortest path, impact/dependency traversal, degree metrics, and connected components.
- Entity alias management with merge proposals, approval/rejection, canonical redirects, split, and resolve workflows.
- Entity manager and entity relations with graph traversal, tags, linked secrets, objects, and envelopes.
- Entity resolution and deduplication.
- HNSW vector index, cosine similarity, vector search, hybrid search, graph neighbors, and analytics.
- Opt-in automatic indexing for KV records, objects, secrets, SQL rows, envelopes, and entity records so normal writes become KG-searchable without per-record `Ingest` calls.
- Query-driven resource graph discovery with `SearchResourceGraph`, which returns matching resources as nodes and explainable inferred relation edges when resources mention the same extracted entities.
- Materialization of inferred resource graph edges into persistent relation records for later graph query and audit.
- Connector interfaces, `ImportConnector`, persistent import jobs, HTTP/CLI job controls, and built-in local file, URL, CSV/TSV/JSON structured-row, and static SQL-row helpers for integrations without mandatory external services.
- Optional host-provided KG authorization filter for embedded production deployments.

## APIs And Interfaces

- Embedded Go APIs in the root package plus feature packages such as `pkg/auth`, `pkg/compliance`, `pkg/kg`, `pkg/s3`, `pkg/sqldriver`, and `pkg/storage`.
- Minimal CLI in `cmd/velocity`.
- Richer command framework in `pkg/cli`.
- Fiber HTTP API in `pkg/web`.
- TCP text command server.
- S3-compatible HTTP surface.
- Enterprise API route group under `/api/v1`.
- Browser admin UI served from `pkg/web/static`.
- Knowledge Graph HTTP, CLI, and admin UI surfaces for ingest, search, graph discovery, persistent relations, ontology, sync status, connector jobs, analytics, and custom NER rules.

## Resilience And Operations

- WAL replay, flush checkpoints, atomic SSTable writes, compaction, repair, and destructive crash/corruption tests.
- Backups, restores, import/export, audit trails, backup verification, and disaster recovery tests.
- Erasure coding, bit rot detection, healing, replication, consistent hashing, cluster state, load balancing, and decommissioning.
- Metrics collection and Prometheus-style rendering interfaces.

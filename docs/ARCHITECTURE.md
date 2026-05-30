# Architecture

## High-Level Shape

Velocity centers on `DB`, an embedded encrypted database. Around that core, the repo layers SQL, object storage, S3 compatibility, HTTP/TCP services, compliance, security, resilience, and knowledge graph features.

```text
Go apps
  -> velocity.DB
      -> memtable + WAL + SSTables + cache + crypto
      -> search indexes
      -> object/envelope/secret/compliance/KG managers

database/sql
  -> pkg/sqldriver
      -> velocity.DB

HTTP/TCP/S3
  -> pkg/web
      -> velocity.DB + user storage + auth middleware
```

## Storage Engine

The root database uses:

- Memtables for recent writes.
- WAL for durability and crash replay.
- SSTables for immutable flushed data.
- Background compaction across levels.
- Bloom filters and sparse indexes for efficient reads.
- Flush checkpoints for recovery around in-progress flushes.
- Optional LRU cache.
- Graceful shutdown hooks that close all registered DBs on process signals.

The default path is `~/.velocity` unless a path is supplied. The minimal CLI defaults to `./velocity_data`.

## Encryption And Keys

The DB carries a crypto provider and master key manager. Data paths include encryption for KV persistence, WAL/SSTable content, object records, envelopes, secrets, and backup signing/integrity helpers.

Master key sources include system file, user-defined key, existing-key detection, cache expiry/clearing, and Shamir share workflows.

## Search Indexes

Search is maintained alongside KV writes when enabled or when using indexed APIs. Index structures track document IDs, doc keys, metadata, token postings, hash postings, and value postings. Search can fall back to scans when indexes cannot satisfy a query.

## SQL Driver

`pkg/sqldriver` registers driver name `velocity`. It implements connections, statements, transactions, execution, and query rows over the embedded DB. The executor parses SQL with `github.com/oarkflow/sqlparser`, stores table metadata and rows in Velocity, and layers constraint enforcement, indexes, row locks, and query cache behavior.

## Object Storage

Native object storage stores object metadata and content beneath DB-managed paths and object directories. It supports stream operations, version metadata, ACLs, tags, custom metadata, folders, thumbnails, hard delete, repair, object lock, and retention.

The S3 layer maps AWS-style bucket/object operations onto the same underlying object and bucket managers.

## Web Server

`pkg/web` uses Fiber v3. It applies helmet, CORS, recovery, logging, and rate limiting middleware. JWT auth protects API routes. Admin routes require the `admin` role. SQLite-backed user storage is used by the server command.

## Enterprise And Governance

Enterprise managers include IAM policies, OIDC/LDAP identity providers, STS, metrics, notifications, lifecycle/tiering, integrity, cluster state, replication, load balancing, and decommissioning.

Compliance managers handle tagging, classification, consent, retention, legal holds, reports, violations, data residency, data masking, breach notifications, and audit trails.

## Knowledge Graph

The KG subsystem extracts content, chunks documents, runs NER, resolves entities, stores entity relations, indexes vectors through HNSW, and exposes search/analytics/graph APIs.


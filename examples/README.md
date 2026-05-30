# Velocity Runnable Cookbook

These examples are small, runnable programs that exercise Velocity's main configuration and feature surfaces. Run them from this directory:

```bash
go run ./config_cookbook
go run ./kv_search_cookbook
go run ./sql_driver_cookbook
go run ./object_storage_cookbook
go run ./s3_bucket_cookbook
go run ./compliance_governance_cookbook
go run ./identity_security_cookbook
go run ./kg_cookbook
go run ./backup_resilience_cookbook
```

Each cookbook uses temporary local directories and does not require cloud credentials, external services, open ports, or persistent state.

## Cookbook Coverage

| Cookbook | Covers |
| --- | --- |
| `config_cookbook` | `velocity.Config`, master key config, upload limits, performance flags, search schemas, SQL query cache fields |
| `kv_search_cookbook` | KV CRUD, TTL, counters, key scans/pages, default and per-prefix search schemas, filters, boolean conditions, highlights, index rebuild |
| `sql_driver_cookbook` | `database/sql`, Velocity SQL driver, `sqldriver.DSNConfigs`, DSN query-cache params, CRUD, transactions, joins, bulk insert |
| `object_storage_cookbook` | Object options, stream APIs, ACLs, metadata/tags, listing, versioning, hard/soft delete, V2 object requests, repair dry-run |
| `s3_bucket_cookbook` | Buckets, encryption, quotas, versioning, object lock, replication, S3-style copy/range/tag/head, credentials, presigned URLs |
| `compliance_governance_cookbook` | Compliance tags, inheritance, classification, masking, retention, residency, audit events, violations |
| `identity_security_cookbook` | MFA, RBAC, IAM policies, STS temporary credentials |
| `kg_cookbook` | KG ingest options, custom extractor/chunker/NER, deterministic embeddings, HNSW, keyword/semantic/hybrid search, reranker |
| `backup_resilience_cookbook` | Backup, restore, export, import, WAL tuning, erasure coding, healing/repair dry-run |

## Existing Larger Demos

The repository also includes end-to-end demos for specific workflows:

- `s3_demo` for a broader S3 compatibility walkthrough.
- `hardened_object_workflow` for object hardening, presigned URLs, and repair.
- `encrypted_search_demo`, `fulltext_demo`, and `search_index_large_demo` for search-focused workflows.
- `sql_complete_demo`, `sql_crud_demo`, and `sql_million_demo` for SQL coverage.
- `compliance_full_demo`, `enterprise_compliance_demo`, `multiple_tags_demo`, and `tag_update_demo` for compliance workflows.
- `kg_batch_demo`, `kg_search_demo`, and `kg_ner_demo` for knowledge graph workflows.


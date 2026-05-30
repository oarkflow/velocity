# Testing

Velocity has broad tests across the engine, SQL driver, object/S3 layer, compliance, envelopes, security, and KG components.

## Recommended Checks

List Markdown docs after rebuild:

```bash
find . -name '*.md' -not -path './.git/*' | sort
```

Root module tests:

```bash
go test ./...
```

SQL driver:

```bash
go test ./pkg/sqldriver
```

Web module:

```bash
cd pkg/web
go test ./...
```

## Heavier Checks

Production suite:

```bash
make test-production
```

Destructive crash/corruption tests:

```bash
make test-destructive
```

Longer destructive soak:

```bash
make test-soak
```

Million-row SQL workload:

```bash
make test-million-sql
```

## Test Areas

- KV durability, wrong-key rejection, WAL replay, WAL truncate/rotation, SSTable repair, atomic writes, flush checkpoint recovery.
- Race and stress tests for counters and multi-key behavior.
- Search indexes, encrypted search, full-text modes, large search datasets, fast JSON scalar extraction.
- Object storage, folder management, S3 credentials, SigV4, buckets, multipart, presigned URLs, object hardening, range requests.
- Compliance tags, multiple tag updates, enterprise compliance features, retention, consent, key rotation.
- Envelopes, custody chain integrity, tamper signals, time locks, access policy enforcement, exports/imports, payload types, replay attack tests.
- SQL CRUD, joins, unions, subqueries, complex queries, constraints, transactions, query cache, destructive SQL, million-row workload.
- Knowledge graph extraction, chunking, NER, entity resolution, HNSW, engine ingest/search.
- Web pentest-style tests that intentionally document security risks and abuse surfaces.

## Current Makefile Caveat

Some Makefile targets reference `cmd/secretr` and `internal/secretr`, which are absent or empty in this checkout. Prefer direct `go test` commands above unless those paths are restored.


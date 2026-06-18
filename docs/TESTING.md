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

Reliability and disaster-recovery gate:

```bash
./scripts/reliability_suite.sh quick
./scripts/reliability_suite.sh full
./scripts/reliability_suite.sh soak
./scripts/reliability_suite.sh race
```

Equivalent Make targets:

```bash
make reliability
make reliability-full
make reliability-soak
make reliability-race
```

Tiers:

- `quick`: focused KV durability, WAL replay/rotation/truncation, corruption rejection, backup/restore, reactive determinism, SQL transaction durability, web API/security tests, and the reactive example smoke test.
- `full`: `quick` plus the root package suite, examples compile/test suite, and destructive crash/corruption tests for KV and SQL.
- `soak`: `full` plus longer destructive child-process crash matrices. Tune with `VELOCITY_DESTRUCTIVE_SOAK_ITERS=1200`.
- `race`: focused reliability-sensitive suites under Go's race detector.

Opt into the million-row SQL workload during soak:

```bash
VELOCITY_RELIABILITY_MILLION=1 ./scripts/reliability_suite.sh soak
```

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

Some legacy Makefile targets reference `cmd/secretr` and `internal/secretr`, which are absent or empty in this checkout. The `reliability*`, `test-production`, `test-destructive`, `test-soak`, and direct `go test` commands above target the current Velocity packages.

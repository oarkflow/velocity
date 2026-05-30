# Limitations And Current Gaps

This page records important source-discovered caveats.

## Repository Inconsistencies

- `Makefile` references `cmd/secretr` and `internal/secretr`, but this checkout only shows `cmd/velocity` and an empty/absent `internal` tree. Targets such as `build-secretr`, `test-go`, and CLI test targets may fail until those paths are restored or the Makefile is updated.
- `scripts/velocity.sh` defaults `VELOCITY_BIN` to `./scripts/velocity`, while the usual build command creates `./velocity`.
- The root Makefile mentions a comprehensive Secretr CLI test script path that is not present in the inspected file list.

## CLI Surface Mismatch

- `cmd/velocity` is a small manual CLI for data, secret, object, and envelope operations.
- `pkg/cli` contains a richer command registry and command builders for backup/data/envelope/folder/object/secret, but this framework is not evidently connected to `cmd/velocity`.
- Documentation should treat `pkg/cli` as a framework/library surface until a binary entrypoint wires it in.

## HTTP/API Caveats

- `pkg/web/http_server.go` registers `POST /api/put`, `GET /api/get/:key`, and `DELETE /api/delete/:key` twice.
- Enterprise routes are not automatically part of `NewHTTPServer`; they require an app to construct `EnterpriseAPI` and call `RegisterRoutes`.
- S3 routes are implemented by `S3API.RegisterRoutes`; a host must register them explicitly where needed.

## SQL Limitations

- Recursive CTEs are rejected.
- Composite primary key and composite unique constraints are rejected.
- Inserts require explicit column lists.
- SQL behavior is substantial but not a complete SQL standard implementation.

## Security Caveats

- Pentest-style tests identify risk areas around default JWT secret handling, object version enumeration/IDOR, ACL update authorization, route shadowing, missing username claim behavior, and search abuse surfaces.
- Benchmark-only flags can disable encryption, WAL, fsync, index persistence, or close flushing.
- Public exposure of the HTTP server should include explicit JWT secret configuration, user bootstrap review, network controls, TLS/proxy configuration, and route-by-route security testing.

## Production Wiring

Many enterprise, compliance, metrics, notification, lifecycle, cluster, replication, and resilience components are available as libraries/managers. They may need explicit initialization and route registration by the host application.

## Documentation Boundary

This docs set reflects the current source tree. It does not claim external certification for compliance frameworks, S3 completeness, SQL standard completeness, or production readiness in every deployment shape.


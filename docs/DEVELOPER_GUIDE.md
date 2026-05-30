# Developer Guide

## Package Layout

- Root package `github.com/oarkflow/velocity`: embedded `DB`, storage engine integration, WAL/SSTable/memtable code, DB-owned methods, search integration, object integration, retention enforcement, and managers that still require direct `DB` internals.
- `cmd/velocity`: minimal user-facing CLI.
- `pkg/auth`: IAM policy engine, RBAC, MFA, access reviews, and segregation-of-duties managers. Use this package directly; there are no root aliases.
- `pkg/compliance`: framework/classification enums plus consent records and consent manager. Root compliance tag APIs use these package types where applicable.
- `pkg/core`: reusable core primitives such as consistent hashing.
- `pkg/kg`: knowledge graph engine, resource graph, extraction, chunking, NER, HNSW/vector search, and text query implementation.
- `pkg/s3`: S3 and bucket implementation: credential store, SigV4, bucket manager, bucket versioning, multipart, presigned URLs, range helpers, and wire types.
- `pkg/sqldriver`: `database/sql` driver.
- `pkg/storage`: reusable storage helpers such as cache modes.
- `pkg/web`: separate module for HTTP/TCP server, S3 API, admin UI, and user storage.
- `pkg/cli`: command-builder framework and richer command implementations.
- `benchmarks/sql_comparison`: comparative SQL benchmarks.
- `examples`: runnable feature cookbooks.

## Opening A Database

Use `New` for defaults or `NewWithConfig` for explicit configuration:

```go
db, err := velocity.NewWithConfig(velocity.Config{
	Path:              "./data",
	PerformanceMode:   "balanced",
	SearchIndexEnabled: true,
})
```

Important config fields include `Path`, `EncryptionKey`, `MasterKey`, `MasterKeyConfig`, `MaxUploadSize`, `PerformanceMode`, `SearchSchema`, `SearchSchemas`, `NodeID`, `JWTSecret`, and benchmark-only durability/index flags.

## Public API Families

- KV: `Put`, `PutWithTTL`, `Get`, `Delete`, `Has`, `Keys`, `KeysPage`, `Scan`, `Incr`, `Decr`, `TTL`.
- Search: `PutIndexed`, `PutWithIndexFieldPairs`, `SetSearchSchema`, `SetSearchSchemaForPrefix`, `EnableSearchIndex`, `RebuildIndex`, `Search`, `SearchCount`.
- Batch: `NewBatchWriter`.
- Objects: `StoreObject`, `StoreObjectStream`, `GetObject`, `GetObjectStream`, `DeleteObject`, `HardDeleteObject`, `ListObjects`, folder APIs, version APIs, ACL APIs.
- Hardened objects: `PutObject`, `GetObjectStreamV2`, `DeleteObjectV2`, `RepairObjectStorage`.
- Secrets: `CreateSecret`, `RotateSecret`, `GetSecretValue`, `GetSecretRecord`.
- Backups: `Backup`, `Restore`, `Export`, `Import`, backup integrity, and audit chain helpers.
- Envelopes: `CreateEnvelope`, `LoadEnvelope`, `UpdateEnvelope`, custody/tamper/time-lock operations, export/import.
- Entities: `CreateEntity`, `GetEntity`, `QueryEntities`, relation APIs, graph APIs, linked object/secret/envelope helpers.
- Knowledge graph: `KnowledgeGraph`.

## Package-Owned Managers

Several managers now live outside the root package and should be imported directly:

```go
import (
	"github.com/oarkflow/velocity/pkg/auth"
	"github.com/oarkflow/velocity/pkg/compliance"
	"github.com/oarkflow/velocity/pkg/s3"
)

iam := auth.NewIAMPolicyEngine(db)
rbac := auth.NewRBACManager(db)
consent := compliance.NewConsentManager(db)
buckets := s3.NewBucketManager(db, db)
versioning := s3.NewBucketVersioning(db)
```

The root `DB` satisfies the small interfaces these packages need. Avoid adding root aliases for package-owned APIs.

## SQL Driver

Register by importing:

```go
import _ "github.com/oarkflow/velocity/pkg/sqldriver"
```

Open with:

```go
db, err := sql.Open("velocity", "./sql_data")
```

See [SQL Driver](SQL_DRIVER.md).

## Web Module Development

`pkg/web` is a separate module. Work from that directory when running its server or tests:

```bash
cd pkg/web
go test ./...
go run ./cmd serve --http 8081 --tcp 8080
```

The module uses Fiber v3, JWT, SQLite user storage, and a local `replace` to the root module.

## Examples

Use the examples as implementation sketches. They cover KV, SQL, object storage, S3, compliance, security, KG, envelopes, backups, and production features. See [Examples](EXAMPLES.md).

## Development Notes

- Prefer source and tests over old docs when resolving behavior.
- Some Makefile targets reference absent `cmd/secretr` and `internal/secretr` paths in this checkout.
- Some packages expose feature managers that are not automatically wired into the shipped minimal CLI.
- Benchmark-only config flags can trade away durability or security and should not be used in production flows.

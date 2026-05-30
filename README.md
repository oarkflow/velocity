# Velocity

Velocity is an embedded Go storage engine and server toolkit that combines an encrypted key/value database with object storage, SQL access, search indexing, compliance controls, secure envelopes, and knowledge graph capabilities.

The main Go module is `github.com/oarkflow/velocity` and currently declares Go `1.26.0`.

## What Is Included

- Embedded encrypted KV database with WAL, memtables, SSTables, TTL, scans, pagination, increments, batch writes, cache modes, and graceful shutdown.
- SQL driver under `pkg/sqldriver` registered as `velocity` for use with `database/sql`.
- Native object and folder storage with metadata, ACLs, versioning, object lock, previews, thumbnails, and repair paths.
- S3-compatible package and route layer with SigV4 authentication, buckets, objects, range reads, multipart upload, tagging, presigned URLs, and bucket-level features.
- HTTP and TCP servers in the separate `pkg/web` module.
- JWT auth, admin endpoints, master key management endpoints, and a browser admin UI.
- Enterprise subsystems for IAM/RBAC auth policies, STS, OIDC, LDAP, metrics, lifecycle, notifications, integrity, cluster state, replication, and storage tiering.
- Security and compliance features including master keys, Shamir workflows, FIPS crypto helpers, MFA, audit trails, retention, consent, data residency, classification, masking, and breach notification.
- Knowledge graph ingestion, chunking, entity extraction, entity resolution, HNSW/vector search, graph traversal, and analytics.

## Quick Start

Use Velocity as an embedded library:

```go
package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	db, err := velocity.New("./velocity_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Put([]byte("hello"), []byte("world")); err != nil {
		log.Fatal(err)
	}
	value, err := db.Get([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(value))
}
```

Build the minimal CLI:

```bash
go build -o velocity ./cmd/velocity
./velocity data put hello world
./velocity data get hello
```

Run the HTTP/TCP server module:

```bash
cd pkg/web
go run ./cmd serve --http 8081 --tcp 8080 --dir ./velocitydb_server
```

## Repository Map

- `velocity.go` and root `*.go`: core embedded database integration, WAL/SSTable/memtable engine, DB methods, search, object integration, retention enforcement, and root-owned enterprise managers that need direct `DB` internals.
- `cmd/velocity`: small shipped CLI for data, secret, object, envelope, and compliance tag/check operations.
- `pkg/auth`: IAM policy engine, RBAC, MFA, access reviews, and segregation-of-duties managers.
- `pkg/compliance`: shared compliance enums plus consent records and consent manager.
- `pkg/core`: reusable core primitives such as consistent hashing.
- `pkg/kg`: knowledge graph engine, resource graph, chunking, extraction, NER, HNSW/vector search, and text query implementation.
- `pkg/s3`: S3/bucket package code including credential store, SigV4, bucket manager, bucket versioning, multipart, presigned URLs, and S3 helper types.
- `pkg/sqldriver`: `database/sql` driver and SQL executor.
- `pkg/storage`: reusable storage helpers such as cache modes.
- `pkg/web`: separate Go module with Fiber HTTP APIs, TCP server, S3 API, admin UI assets, and user storage.
- `pkg/cli`: richer command framework for backup/data/envelope/folder/object/secret commands; not currently wired into `cmd/velocity`.
- `examples`: runnable feature demonstrations.
- `benchmarks`: SQL comparison and differential benchmark programs.
- `docs`: curated documentation set.

## Documentation

Start with [docs/README.md](docs/README.md).

Key guides:

- [Getting Started](docs/GETTING_STARTED.md)
- [Code And Command Cookbook](docs/COOKBOOK.md)
- [Feature Catalog](docs/FEATURES.md)
- [User Guide](docs/USER_GUIDE.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Operations](docs/OPERATIONS.md)
- [Limitations](docs/LIMITATIONS.md)

## Current Status

Velocity has broad test coverage across the KV engine, SQL driver, object storage, S3 behavior, security controls, compliance tags, envelopes, knowledge graph components, and destructive crash/corruption scenarios. The checkout also contains inconsistencies that are documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), including Makefile references to absent `cmd/secretr` and `internal/secretr` code.

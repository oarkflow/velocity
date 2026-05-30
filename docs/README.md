# Velocity Documentation

This documentation set was rebuilt from the current source tree. It is organized by audience and subsystem rather than by the older one-file-per-feature layout.

## Start Here

- New users: [Getting Started](GETTING_STARTED.md), then [User Guide](USER_GUIDE.md).
- Developers embedding Velocity: [Developer Guide](DEVELOPER_GUIDE.md), [API Reference](API_REFERENCE.md), and [SQL Driver](SQL_DRIVER.md).
- Operators: [Operations](OPERATIONS.md), [Security](SECURITY.md), and [Testing](TESTING.md).
- Technical evaluators: [Architecture](ARCHITECTURE.md), [Feature Catalog](FEATURES.md), [Compliance](COMPLIANCE.md), and [Limitations](LIMITATIONS.md).
- Anyone looking for copy-paste usage: [Code And Command Cookbook](COOKBOOK.md).

## Core References

- [Features](FEATURES.md): complete feature inventory grouped by subsystem.
- [API Reference](API_REFERENCE.md): Go, HTTP, S3, KG, enterprise, admin, and auth APIs.
- [CLI Reference](CLI_REFERENCE.md): shipped `cmd/velocity` commands and the separate `pkg/cli` framework.
- [Object and S3](OBJECT_AND_S3.md): native object storage and S3-compatible behavior.
- [Knowledge Graph](KNOWLEDGE_GRAPH.md): ingestion, search, graph, and analytics.
- [Examples](EXAMPLES.md): map of runnable example programs.
- [Cookbook](COOKBOOK.md): Go snippets plus CLI, curl, and `go run` commands for each major subsystem.

## Source Truth Notes

- Main module: `github.com/oarkflow/velocity`.
- Go version in `go.mod`: `1.26.0`.
- `pkg/web` is its own Go module and replaces the root module locally.
- Current feature package split: `pkg/auth` owns IAM/RBAC/MFA/access reviews/SoD, `pkg/compliance` owns compliance enums and consent management, `pkg/s3` owns S3 and bucket managers, `pkg/kg` owns knowledge graph implementation, `pkg/storage` owns reusable cache helpers, and `pkg/core` owns reusable primitives.
- `docs/api_tests.http` is preserved as an API exercise file, not part of the Markdown docs set.

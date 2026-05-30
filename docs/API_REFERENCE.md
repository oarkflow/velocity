# API Reference

This reference summarizes the API surfaces visible in the current source tree.

## Go Embedded API

Open a database:

```go
db, err := velocity.New("./data")
db, err := velocity.NewWithConfig(velocity.Config{Path: "./data"})
```

Core methods:

- `Put`, `PutWithTTL`, `Get`, `Delete`, `Has`, `HasString`
- `Incr`, `Decr`, `TTL`
- `Keys`, `KeysPage`, `Scan`
- `Close`, `GetWAL`, `MasterKey`, `NodeID`, `JWTSecret`
- `EnableCache`, `SetCacheMode`, `SetPerformanceMode`
- `NewBatchWriter`

Search:

- `PutIndexed`
- `PutWithIndexFieldPairs`
- `SetSearchSchema`
- `SetSearchSchemaForPrefix`
- `EnableSearchIndex`
- `RebuildIndex`
- `ClearIndexForPrefix`
- `DeleteIndexed`
- `Search`
- `SearchCount`

Objects:

- `StoreObject`, `StoreObjectStream`
- `GetObject`, `GetObjectStream`
- `DeleteObject`, `HardDeleteObject`
- `ListObjects`
- `CreateFolder`, `CreateFolders`, `DeleteFolder`, `DeleteFolderRecursive`, `ListFolders`
- `GetObjectMetadata`, `GetObjectACL`, `GetObjectVersion`
- `PutObject`, `GetObjectStreamV2`, `DeleteObjectV2`, `RepairObjectStorage`

Security, compliance, and governance APIs are exposed through manager constructors and DB convenience methods documented in the subsystem guides.

Compliance resources:

- `ComplianceResourceType`
- `ComplianceResourceRef`
- `ComplianceTag.ResourceType`
- `ComplianceTag.ResourceID`
- `ComplianceTag.ResourceRef`
- `ComplianceOperationRequest.ResourceType`
- `ComplianceOperationRequest.ResourceID`
- `ComplianceOperationRequest.ResourceRef`

Compliance tag manager APIs:

- `TagResource(ctx, ref, tag)`
- `GetResourceTag(ref)`
- `GetResourceTags(ref)`
- `RemoveResourceTag(ctx, ref)`
- `ValidateResourceOperation(ctx, ref, req)`
- Compatibility wrappers: `TagPath`, `GetTag`, `GetTags`, `RemoveTag`, `ValidateOperation`

Canonical resource examples:

- `kv:/users/1`
- `object:/reports/q1.pdf`
- `bucket:archive`
- `secret:api-key`
- `secret_version:api-key:v1`
- `sql:schema:main`
- `sql:table:main.patients`
- `sql:column:main.patients.ssn`
- `sql:row:main.patients/123`

## HTTP Auth

Public route:

- `POST /auth/login`: accepts `username` and `password`, returns a JWT.

Most `/api`, `/api/objects`, `/api/folders`, `/api/versions`, and `/admin` routes require:

```http
Authorization: Bearer <token>
```

JWT claims must include a non-empty `username`. `role` must be `user` or `admin`; admin routes require `admin`.

## HTTP KV And File API

Protected `/api` routes:

- `POST /api/put`: store key/value data.
- `GET /api/get/:key`: retrieve a value.
- `DELETE /api/delete/:key`: delete a key.
- `POST /api/indexed`: store indexed JSON/data.
- `POST /api/search`: search indexed data.
- `GET /api/keys`: list keys with pagination.
- `POST /api/files`: upload a file.
- `GET /api/files`: list files.
- `GET /api/files/:key/meta`: file metadata.
- `GET /api/files/:key`: download a file.
- `GET /api/files/:key/thumbnail`: get a thumbnail.
- `DELETE /api/files/:key`: delete a file.

The current route setup registers `POST /api/put`, `GET /api/get/:key`, and `DELETE /api/delete/:key` twice; behavior is effectively duplicate registration in source.

## Native Object HTTP API

Protected `/api/objects` routes:

- `GET /api/objects/`: list objects.
- `POST /api/objects/*`: upload multipart file data to an object path.
- `GET /api/objects/*`: download object data.
- `DELETE /api/objects/*`: delete object data.
- `HEAD /api/objects/*`: object headers.
- `GET /api/objects/meta/*`: object metadata.
- `PUT /api/objects/acl/*`: update ACL.
- `GET /api/objects/acl/*`: read ACL.

Protected folder routes:

- `POST /api/folders/*`: create folder.
- `DELETE /api/folders/*`: delete folder.

Protected version routes:

- `GET /api/versions/*`: list versions for an object path.
- `GET /api/versions/:versionId/*`: get a specific version.

## Admin API

Protected admin-only routes:

- `GET /admin/wal`
- `POST /admin/wal/rotate`
- `GET /admin/wal/archives`
- `POST /admin/sstable/repair`
- `GET /admin/masterkey/config`
- `POST /admin/masterkey/config`
- `POST /admin/masterkey/refresh`
- `DELETE /admin/masterkey/cache`
- `GET /admin/masterkey/cache/info`
- `POST /admin/thumbnails/regenerate`
- `POST /admin/thumbnails/:key/regenerate`
- `DELETE /admin/thumbnails/:key`

Static UI:

- `GET /admin`
- `GET /admin-ui*`
- `GET /static*`

## Knowledge Graph API

Routes under `/api/v1/kg`:

- `POST /ingest`
- `POST /ingest/batch`
- `POST /search`
- `GET /documents/:id`
- `DELETE /documents/:id`
- `GET /graph/:entity_id?depth=1`
- `GET /analytics`

## Enterprise API

Routes under `/api/v1`:

- IAM: `POST /iam/policies`, `GET /iam/policies`, `GET /iam/policies/:name`, `DELETE /iam/policies/:name`, `POST /iam/attach`, `POST /iam/detach`, `POST /iam/evaluate`.
- OIDC: `GET /auth/oidc/login`, `GET /auth/oidc/callback`.
- LDAP: `POST /auth/ldap/login`.
- STS: `POST /sts/assume-role`, `POST /sts/web-identity`.
- Metrics: `GET /metrics`.
- Notifications: `PUT`, `GET`, `DELETE /buckets/:bucket/notifications`.
- Lifecycle: `PUT`, `GET`, `DELETE /buckets/:bucket/lifecycle`.
- Integrity: `GET /integrity/status`, `GET /integrity/object`.
- Cluster: `GET /cluster/status`, `GET /cluster/nodes`.

Enterprise routes are registered only when `EnterpriseAPI.RegisterRoutes` is called by the hosting program.

## S3-Compatible API

Routes under `/s3`, protected by SigV4 auth middleware:

- `GET /s3/`: list buckets.
- `PUT /s3/:bucket`: create bucket.
- `DELETE /s3/:bucket`: delete bucket.
- `HEAD /s3/:bucket`: bucket existence.
- `GET /s3/:bucket`: bucket operations selected by query parameters.
- `HEAD /s3/:bucket/*`: object metadata.
- `GET /s3/:bucket/*`: get object with range and conditional header support.
- `PUT /s3/:bucket/*`: put object, copy object, or upload multipart part depending on headers/query.
- `DELETE /s3/:bucket/*`: delete object.
- `POST /s3/:bucket/*`: multipart completion and related object operations.

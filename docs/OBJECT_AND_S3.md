# Object And S3 Storage

Velocity has two object layers: native object APIs and an S3-compatible HTTP API.

## Native Object API

Core methods:

- `StoreObject`
- `StoreObjectStream`
- `GetObject`
- `GetObjectStream`
- `DeleteObject`
- `HardDeleteObject`
- `ListObjects`
- `GetObjectMetadata`
- `GetObjectACL`
- `GetObjectVersion`

Objects support:

- Content type and size metadata.
- Owner and ACL information.
- Public objects.
- Tags and custom metadata.
- Stream upload/download.
- Version IDs and delete markers.
- Hard delete.
- Folder-style organization.

## Hardened Object API

The newer request/response API includes:

- `PutObject`
- `GetObjectStreamV2`
- `DeleteObjectV2`
- `RepairObjectStorage`

Associated features include checksum validation, encrypted object records, object retention info, delete markers, object lock enforcement, and repair reports.

## Folders

Folder methods include:

- `CreateFolder`
- `CreateFolders`
- `DeleteFolder`
- `DeleteFolderRecursive`
- `ListFolders`
- copy/rename helpers in the CLI command framework
- browser preview flows through folder view helpers

## HTTP Native Object Routes

Protected routes:

- `GET /api/objects/`
- `POST /api/objects/*`
- `GET /api/objects/*`
- `DELETE /api/objects/*`
- `HEAD /api/objects/*`
- `GET /api/objects/meta/*`
- `PUT /api/objects/acl/*`
- `GET /api/objects/acl/*`
- `POST /api/folders/*`
- `DELETE /api/folders/*`
- `GET /api/versions/*`
- `GET /api/versions/:versionId/*`

## S3-Compatible API

S3 implementation types live in `github.com/oarkflow/velocity/pkg/s3`; root `DB` supplies the object/KV interfaces those managers need.

Go:

```go
import "github.com/oarkflow/velocity/pkg/s3"

creds := s3.NewS3CredentialStore(db, db)
sigv4 := s3.NewSigV4Auth(creds, "us-east-1")
buckets := s3.NewBucketManager(db, db)
multipart := s3.NewMultipartManager(db)
versioning := s3.NewBucketVersioning(db)
_ = sigv4
_ = buckets
_ = multipart
_ = versioning
```

S3 routes are mounted under `/s3` and protected by SigV4 auth middleware:

- Buckets: list, create, delete, head.
- Objects: get, put, head, delete.
- Copy object through `x-amz-copy-source`.
- Range and conditional reads.
- Multipart upload dispatch through query parameters.
- Object tagging.
- Bucket versioning, replication, lifecycle, notification, quota, and encryption-related structures.
- Presigned URLs.

## Useful Examples

- `examples/object_storage_cookbook/main.go`
- `examples/folder_management_demo/main.go`
- `examples/hardened_object_workflow/main.go`
- `examples/s3_demo/main.go`
- `examples/s3_bucket_cookbook/main.go`

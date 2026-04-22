# Velocity — Usage Guide

Velocity is a production-grade, S3-compatible object storage system built on an LSM-tree engine. It provides a full S3 API (SigV4 authentication, buckets, objects, multipart uploads, versioning), an enterprise REST API (IAM, metrics, lifecycle, integrity, cluster), and an admin UI.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Server Architecture](#server-architecture)
3. [Running the Server](#running-the-server)
4. [S3 API Reference](#s3-api-reference)
5. [Enterprise API Reference](#enterprise-api-reference)
6. [REST API (JWT)](#rest-api-jwt)
7. [Admin API](#admin-api)
8. [Authentication](#authentication)
9. [Configuration](#configuration)
10. [Library Usage (Go)](#library-usage-go)

---

## Quick Start

```bash
# From the project root
cd examples
go run ./full_server
```

The server starts on port **9000** and prints the generated S3 credentials:

```
=== Velocity Server starting on port 9000 ===
  Admin UI:      http://localhost:9000/admin-ui
  S3 API:        http://localhost:9000/s3/
  Enterprise:    http://localhost:9000/api/v1/
  REST API:      http://localhost:9000/api/
  Metrics:       http://localhost:9000/api/v1/metrics
  JWT login:     POST http://localhost:9000/auth/login

AWS CLI config:
  aws configure
  AWS Access Key ID:     <generated>
  AWS Secret Access Key: <generated>
  Default region:        us-east-1
```

### Quick test with curl

```bash
# Login to get a JWT token
TOKEN=$(curl -s -X POST http://localhost:9000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password123"}' | jq -r .token)

# Store a key-value pair
curl -X POST http://localhost:9000/api/put \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"hello","value":"world"}'

# Retrieve it
curl http://localhost:9000/api/get/hello \
  -H "Authorization: Bearer $TOKEN"
```

---

## Server Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Fiber HTTP Server                   │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Admin UI │  │ REST API │  │ Object Storage API│  │
│  │ /admin-ui│  │ /api/*   │  │ /api/objects/*    │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
│  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │ S3 API (/s3)     │  │ Enterprise API (/api/v1) │  │
│  │ SigV4 auth       │  │ IAM, Metrics, Lifecycle  │  │
│  │ XML responses    │  │ Integrity, Cluster       │  │
│  └──────────────────┘  └──────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│                Velocity Core Library                 │
│  DB · Buckets · Objects · Multipart · Versioning    │
│  IAM · Metrics · Erasure · Replication · Tiering    │
│  Notifications · Integrity · Cluster · Object Lock  │
└────────────────────────────────────────���────────────┘
```

### Subsystem Summary

| Subsystem | Description |
|---|---|
| **S3CredentialStore** | Manages S3 access keys (generate, get, delete) |
| **SigV4Auth** | AWS Signature V4 request verification |
| **BucketManager** | S3 bucket CRUD, versioning, encryption config |
| **MultipartManager** | Multipart upload lifecycle (initiate, upload part, complete, abort) |
| **PresignedURLGenerator** | Pre-signed URL creation for temporary access |
| **IAMPolicyEngine** | Policy CRUD, user/group attachment, access evaluation |
| **MetricsCollector** | Prometheus-compatible counters, gauges, histograms |
| **StorageTierManager** | Storage class transitions + lifecycle rules |
| **NotificationManager** | Bucket event notifications (webhook, callback) |
| **IntegrityManager** | Bit-rot detection, erasure coding, auto-healing |
| **ClusterManager** | Multi-node cluster with consistent hashing |
| **DecommissionManager** | Safe node removal with data migration |
| **ObjectLockManager** | WORM: COMPLIANCE and GOVERNANCE modes |

---

## Running the Server

### Full server example (recommended)

```bash
cd examples
go run ./full_server
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `VELOCITY_DATA_DIR` | `./velocity_data` | Database directory |
| `VELOCITY_PORT` | `9000` | HTTP listen port |
| `VELOCITY_USERS_DB` | `./users.db` | SQLite user database path |

### Web module standalone server

```bash
cd web
go run ./cmd/main.go serve --http 8081 --tcp 8080 --dir ./data
```

---

## S3 API Reference

All S3 endpoints live under `/s3` and require **AWS Signature V4** authentication.

### Configure AWS CLI

```bash
aws configure
# Enter the access key and secret printed at startup
# Region: us-east-1
# Output format: json

# Set endpoint for all commands
export AWS_ENDPOINT=http://localhost:9000
```

### Bucket Operations

#### Create bucket

```bash
# AWS CLI
aws --endpoint-url $AWS_ENDPOINT s3 mb s3://my-bucket

# curl
curl -X PUT http://localhost:9000/s3/my-bucket \
  -H "Authorization: AWS4-HMAC-SHA256 ..."

# With location constraint (XML body)
curl -X PUT http://localhost:9000/s3/my-bucket \
  -d '<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>'
```

#### List buckets

```bash
aws --endpoint-url $AWS_ENDPOINT s3 ls
# or
curl http://localhost:9000/s3/
```

**Response** (XML):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>admin</ID>
    <DisplayName>admin</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>my-bucket</Name>
      <CreationDate>2024-01-15T10:30:00Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>
```

#### Head bucket

```bash
aws --endpoint-url $AWS_ENDPOINT s3api head-bucket --bucket my-bucket
```

Returns `200 OK` with `x-amz-bucket-region` header, or `404` if not found.

#### Delete bucket

```bash
aws --endpoint-url $AWS_ENDPOINT s3 rb s3://my-bucket
```

Returns `204 No Content` on success. Fails with `409 BucketNotEmpty` if bucket has objects.

### Object Operations

#### Upload an object

```bash
# AWS CLI
aws --endpoint-url $AWS_ENDPOINT s3 cp myfile.txt s3://my-bucket/docs/myfile.txt

# curl
curl -X PUT http://localhost:9000/s3/my-bucket/docs/myfile.txt \
  -H "Content-Type: text/plain" \
  -H "x-amz-storage-class: STANDARD" \
  -H "x-amz-tagging: project=demo&env=test" \
  -H "x-amz-meta-author: alice" \
  --data-binary @myfile.txt
```

**Response headers:**
- `ETag` — MD5 hash of the content
- `x-amz-version-id` — Version ID (if versioning enabled)

#### Download an object

```bash
# AWS CLI
aws --endpoint-url $AWS_ENDPOINT s3 cp s3://my-bucket/docs/myfile.txt ./downloaded.txt

# curl
curl http://localhost:9000/s3/my-bucket/docs/myfile.txt

# With range request
curl -H "Range: bytes=0-99" http://localhost:9000/s3/my-bucket/docs/myfile.txt
```

**Supported headers:**
- `Range: bytes=start-end` — Partial content (returns `206`)
- `If-Match` / `If-None-Match` — Conditional on ETag
- `If-Modified-Since` / `If-Unmodified-Since` — Conditional on date

#### Get a specific version

```bash
curl "http://localhost:9000/s3/my-bucket/docs/myfile.txt?versionId=abc123"
```

#### Head object

```bash
aws --endpoint-url $AWS_ENDPOINT s3api head-object --bucket my-bucket --key docs/myfile.txt
```

Returns metadata headers without body: `Content-Type`, `Content-Length`, `ETag`, `Last-Modified`, `x-amz-version-id`, `x-amz-storage-class`, `x-amz-server-side-encryption`, `x-amz-meta-*`.

#### Delete an object

```bash
aws --endpoint-url $AWS_ENDPOINT s3 rm s3://my-bucket/docs/myfile.txt
```

#### Copy an object (server-side)

```bash
# AWS CLI
aws --endpoint-url $AWS_ENDPOINT s3 cp s3://my-bucket/a.txt s3://my-bucket/b.txt

# curl (uses x-amz-copy-source header)
curl -X PUT http://localhost:9000/s3/my-bucket/copy-of-a.txt \
  -H "x-amz-copy-source: my-bucket/a.txt"
```

**Response** (XML):
```xml
<CopyObjectResult>
  <LastModified>2024-01-15T12:00:00Z</LastModified>
  <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
</CopyObjectResult>
```

### List Objects (ListObjectsV2)

```bash
# All objects
aws --endpoint-url $AWS_ENDPOINT s3 ls s3://my-bucket --recursive

# With prefix filter
curl "http://localhost:9000/s3/my-bucket?prefix=docs/&delimiter=/&max-keys=100"
```

**Query parameters:**
- `prefix` — Filter by key prefix
- `delimiter` — Group common prefixes (virtual directories)
- `max-keys` — Maximum results (default: 1000)
- `start-after` — Start listing after this key
- `continuation-token` — Resume from previous truncated response

### Bucket Versioning

```bash
# Get versioning status
curl "http://localhost:9000/s3/my-bucket?versioning"
```

### Multipart Upload

For large files (>5MB recommended), use multipart upload:

```bash
# 1. Initiate
UPLOAD_ID=$(curl -s -X POST "http://localhost:9000/s3/my-bucket/bigfile.bin?uploads" \
  | xmllint --xpath '//UploadId/text()' -)

# 2. Upload parts
curl -X PUT "http://localhost:9000/s3/my-bucket/bigfile.bin?uploadId=$UPLOAD_ID&partNumber=1" \
  --data-binary @part1.bin

curl -X PUT "http://localhost:9000/s3/my-bucket/bigfile.bin?uploadId=$UPLOAD_ID&partNumber=2" \
  --data-binary @part2.bin

# 3. Complete (provide part ETags)
curl -X POST "http://localhost:9000/s3/my-bucket/bigfile.bin?uploadId=$UPLOAD_ID" \
  -d '<CompleteMultipartUpload>
        <Part><PartNumber>1</PartNumber><ETag>"etag1"</ETag></Part>
        <Part><PartNumber>2</PartNumber><ETag>"etag2"</ETag></Part>
      </CompleteMultipartUpload>'

# Abort (if needed)
curl -X DELETE "http://localhost:9000/s3/my-bucket/bigfile.bin?uploadId=$UPLOAD_ID"

# List active uploads
curl "http://localhost:9000/s3/my-bucket?uploads"
```

### S3 Error Format

All errors return standard S3 XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
  <Resource>my-bucket</Resource>
  <RequestId>1705312200000000000</RequestId>
</Error>
```

Common error codes: `AccessDenied`, `NoSuchBucket`, `NoSuchKey`, `BucketAlreadyOwnedByYou`, `BucketNotEmpty`, `InvalidBucketName`, `NoSuchUpload`, `InvalidPart`, `SignatureDoesNotMatch`, `InvalidAccessKeyId`.

---

## Enterprise API Reference

Enterprise endpoints live under `/api/v1/`. Authentication is based on the specific subsystem (IAM currently trusts the caller; add middleware as needed).

### IAM Policy Management

#### Create a policy

```bash
curl -X POST http://localhost:9000/api/v1/iam/policies \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ReadOnlyAccess",
    "version": "2012-10-17",
    "statements": [{
      "effect": "Allow",
      "action": ["s3:GetObject", "s3:ListBucket"],
      "resource": ["arn:aws:s3:::my-bucket/*"]
    }]
  }'
```

#### List policies

```bash
curl http://localhost:9000/api/v1/iam/policies
```

#### Get a specific policy

```bash
curl http://localhost:9000/api/v1/iam/policies/ReadOnlyAccess
```

#### Delete a policy

```bash
curl -X DELETE http://localhost:9000/api/v1/iam/policies/ReadOnlyAccess
```

#### Attach policy to user

```bash
curl -X POST http://localhost:9000/api/v1/iam/attach \
  -H 'Content-Type: application/json' \
  -d '{"type":"user","id":"alice","policy_name":"ReadOnlyAccess"}'
```

#### Attach policy to group

```bash
curl -X POST http://localhost:9000/api/v1/iam/attach \
  -H 'Content-Type: application/json' \
  -d '{"type":"group","id":"developers","policy_name":"ReadOnlyAccess"}'
```

#### Detach policy

```bash
curl -X POST http://localhost:9000/api/v1/iam/detach \
  -H 'Content-Type: application/json' \
  -d '{"type":"user","id":"alice","policy_name":"ReadOnlyAccess"}'
```

#### Evaluate access (dry-run)

```bash
curl -X POST http://localhost:9000/api/v1/iam/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "principal": "alice",
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::my-bucket/docs/file.txt"
  }'
```

### Prometheus Metrics

```bash
curl http://localhost:9000/api/v1/metrics
```

Returns Prometheus text exposition format (`text/plain; version=0.0.4`):

```
# HELP velocity_requests_total Total number of requests processed
# TYPE velocity_requests_total counter
velocity_requests_total{method="GET",status="200"} 42
velocity_requests_total{method="PUT",status="200"} 7

# HELP velocity_objects_total Current number of stored objects
# TYPE velocity_objects_total gauge
velocity_objects_total 150

# HELP velocity_request_duration_seconds Histogram of request durations in seconds
# TYPE velocity_request_duration_seconds histogram
velocity_request_duration_seconds_bucket{le="0.001"} 10
velocity_request_duration_seconds_bucket{le="0.01"} 35
velocity_request_duration_seconds_bucket{le="+Inf"} 49
velocity_request_duration_seconds_sum 1.234
velocity_request_duration_seconds_count 49
```

### Bucket Lifecycle

#### Set lifecycle configuration

```bash
curl -X PUT http://localhost:9000/api/v1/buckets/my-bucket/lifecycle \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [{
      "id": "archive-old",
      "status": "Enabled",
      "filter": {"prefix": "logs/"},
      "transitions": [
        {"days": 30, "storage_class": "STANDARD_IA"},
        {"days": 90, "storage_class": "GLACIER"}
      ],
      "expiration": {"days": 365}
    }]
  }'
```

#### Get lifecycle configuration

```bash
curl http://localhost:9000/api/v1/buckets/my-bucket/lifecycle
```

#### Delete lifecycle configuration

```bash
curl -X DELETE http://localhost:9000/api/v1/buckets/my-bucket/lifecycle
```

**Storage classes:** `STANDARD` → `STANDARD_IA` → `GLACIER` → `DEEP_ARCHIVE`

### Bucket Notifications

#### Set notification configuration

```bash
curl -X PUT http://localhost:9000/api/v1/buckets/my-bucket/notifications \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "upload-events",
    "events": ["s3:ObjectCreated:*"],
    "filter_prefix": "uploads/",
    "target": {
      "type": "webhook",
      "endpoint": "https://hooks.example.com/velocity"
    }
  }'
```

#### Get notification configuration

```bash
curl http://localhost:9000/api/v1/buckets/my-bucket/notifications
```

#### Delete notification configuration

```bash
curl -X DELETE http://localhost:9000/api/v1/buckets/my-bucket/notifications
```

### Integrity Status

```bash
curl http://localhost:9000/api/v1/integrity/status
```

**Response:**
```json
{
  "erasure": { "enabled": true, "data_shards": 4, "parity_shards": 2 },
  "bit_rot": { "enabled": true, "objects_scanned": 1000, "corruptions_found": 0 },
  "healing": { "enabled": true, "objects_healed": 5 }
}
```

#### Check specific object integrity

```bash
curl "http://localhost:9000/api/v1/integrity/object?path=my-bucket/docs/file.txt"
```

### Cluster Status

```bash
# Cluster overview
curl http://localhost:9000/api/v1/cluster/status

# All nodes
curl http://localhost:9000/api/v1/cluster/nodes
```

---

## REST API (JWT)

The general-purpose REST API at `/api/*` uses JWT bearer tokens for auth.

### Login

```bash
TOKEN=$(curl -s -X POST http://localhost:9000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password123"}' | jq -r .token)
```

The token is valid for 24 hours.

### Key-Value Operations

```bash
# Put
curl -X POST http://localhost:9000/api/put \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"mykey","value":"myvalue"}'

# Get
curl http://localhost:9000/api/get/mykey \
  -H "Authorization: Bearer $TOKEN"

# Delete
curl -X DELETE http://localhost:9000/api/delete/mykey \
  -H "Authorization: Bearer $TOKEN"

# List keys (paginated)
curl "http://localhost:9000/api/keys?limit=50&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

### Object Storage Operations

```bash
# Upload object (multipart form)
curl -X POST http://localhost:9000/api/objects/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sunset.jpg"

# Download object
curl http://localhost:9000/api/objects/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN" -o sunset.jpg

# Object metadata
curl http://localhost:9000/api/objects/meta/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN"

# Head object
curl -I http://localhost:9000/api/objects/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN"

# Delete object
curl -X DELETE http://localhost:9000/api/objects/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN"

# List objects
curl "http://localhost:9000/api/objects/?prefix=photos/&recursive=true&max_keys=100" \
  -H "Authorization: Bearer $TOKEN"
```

### Folder Operations

```bash
# Create folder
curl -X POST http://localhost:9000/api/folders/documents/reports/ \
  -H "Authorization: Bearer $TOKEN"

# Delete folder
curl -X DELETE http://localhost:9000/api/folders/documents/reports/ \
  -H "Authorization: Bearer $TOKEN"
```

### Version Operations

```bash
# List versions
curl http://localhost:9000/api/versions/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN"

# Get specific version
curl http://localhost:9000/api/versions/v123/photos/sunset.jpg \
  -H "Authorization: Bearer $TOKEN"
```

### Search (with indexing)

```bash
# Store indexed data
curl -X POST http://localhost:9000/api/indexed \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "user:1",
    "value": {"name": "Alice", "age": 30, "department": "engineering"},
    "schema": {
      "fields": [
        {"name": "name", "type": "text", "indexed": true},
        {"name": "age", "type": "number", "indexed": true},
        {"name": "department", "type": "text", "indexed": true}
      ]
    }
  }'

# Full-text search
curl -X POST http://localhost:9000/api/search \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"fullText": "Alice", "limit": 10}'

# Filtered search
curl -X POST http://localhost:9000/api/search \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "prefix": "user:",
    "filters": [{"field": "department", "op": "=", "value": "engineering"}],
    "limit": 50
  }'
```

### File Operations

```bash
# Upload file
curl -X POST http://localhost:9000/api/files \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@photo.jpg" -F "key=myphoto"

# Download file
curl http://localhost:9000/api/files/myphoto \
  -H "Authorization: Bearer $TOKEN" -o photo.jpg

# File metadata
curl http://localhost:9000/api/files/myphoto/meta \
  -H "Authorization: Bearer $TOKEN"

# List files
curl "http://localhost:9000/api/files?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"

# Thumbnail (for images)
curl http://localhost:9000/api/files/myphoto/thumbnail \
  -H "Authorization: Bearer $TOKEN" -o thumb.jpg

# Delete file
curl -X DELETE http://localhost:9000/api/files/myphoto \
  -H "Authorization: Bearer $TOKEN"
```

---

## Admin API

Admin endpoints at `/admin/*` require JWT with `role: admin`.

```bash
# WAL stats
curl http://localhost:9000/admin/wal \
  -H "Authorization: Bearer $TOKEN"

# Rotate WAL
curl -X POST http://localhost:9000/admin/wal/rotate \
  -H "Authorization: Bearer $TOKEN"

# WAL archives
curl http://localhost:9000/admin/wal/archives \
  -H "Authorization: Bearer $TOKEN"

# SSTable repair
curl -X POST http://localhost:9000/admin/sstable/repair \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"path": "/data/sstable-001.sst"}'

# Master key config
curl http://localhost:9000/admin/masterkey/config \
  -H "Authorization: Bearer $TOKEN"

# Regenerate all thumbnails
curl -X POST http://localhost:9000/admin/thumbnails/regenerate \
  -H "Authorization: Bearer $TOKEN"
```

---

## Authentication

### JWT Authentication (REST API)

Used by `/api/*` and `/admin/*` routes.

```bash
# 1. Login
curl -X POST http://localhost:9000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password123"}'

# Response:
# {"token":"eyJ...","expires_in":86400,"user":{"id":1,"username":"admin","role":"admin"}}

# 2. Use the token
curl http://localhost:9000/api/get/mykey \
  -H "Authorization: Bearer eyJ..."
```

### AWS Signature V4 (S3 API)

Used by all `/s3/*` routes. Compatible with any AWS SDK or CLI.

```python
# Python (boto3)
import boto3

s3 = boto3.client('s3',
    endpoint_url='http://localhost:9000',
    aws_access_key_id='<your-access-key>',
    aws_secret_access_key='<your-secret-key>',
    region_name='us-east-1'
)

# Create bucket
s3.create_bucket(Bucket='my-bucket')

# Upload
s3.put_object(Bucket='my-bucket', Key='hello.txt', Body=b'Hello, world!')

# Download
obj = s3.get_object(Bucket='my-bucket', Key='hello.txt')
print(obj['Body'].read())

# List objects
for obj in s3.list_objects_v2(Bucket='my-bucket')['Contents']:
    print(obj['Key'], obj['Size'])
```

```javascript
// Node.js (AWS SDK v3)
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  endpoint: "http://localhost:9000",
  region: "us-east-1",
  credentials: {
    accessKeyId: "<your-access-key>",
    secretAccessKey: "<your-secret-key>",
  },
  forcePathStyle: true,
});

await s3.send(new PutObjectCommand({
  Bucket: "my-bucket",
  Key: "hello.txt",
  Body: "Hello, world!",
}));
```

```go
// Go (AWS SDK v2)
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

cfg, _ := config.LoadDefaultConfig(context.TODO(),
    config.WithCredentialsProvider(
        credentials.NewStaticCredentialsProvider("<access-key>", "<secret-key>", ""),
    ),
    config.WithRegion("us-east-1"),
)

client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("http://localhost:9000")
    o.UsePathStyle = true
})
```

---

## Configuration

### Wiring the full server (Go)

```go
package main

import (
    "context"
    "time"

    "github.com/oarkflow/velocity"
    "github.com/oarkflow/velocity/web"
)

func main() {
    // 1. Core database
    db, _ := velocity.New("./data")
    defer db.Close()

    // 2. S3 credentials & auth
    credStore := velocity.NewS3CredentialStore(db)
    cred, _ := credStore.GenerateCredentials("admin", "bootstrap")
    sigv4 := velocity.NewSigV4Auth(credStore, "us-east-1")

    // 3. Managers
    bucketMgr    := velocity.NewBucketManager(db)
    multipartMgr := velocity.NewMultipartManager(db)
    presigned    := velocity.NewPresignedURLGenerator(credStore, "us-east-1", "http://localhost:9000")
    iamEngine    := velocity.NewIAMPolicyEngine(db)
    metrics      := velocity.NewMetricsCollector()
    tierMgr      := velocity.NewStorageTierManager(db, 24*time.Hour)
    notifMgr     := velocity.NewNotificationManager(db)
    integrityMgr := velocity.NewIntegrityManager(db, velocity.DefaultIntegrityConfig())

    // 4. Start background workers
    notifMgr.Start(context.Background())
    integrityMgr.Start(context.Background())

    // 5. User DB + HTTP server
    userDB, _ := web.NewSQLiteUserStorage("./users.db")
    httpServer := web.NewHTTPServer(db, "9000", userDB)

    // 6. Mount S3 API
    s3api := web.NewS3API(db, bucketMgr, multipartMgr, sigv4, presigned)
    s3api.RegisterRoutes(httpServer.App())

    // 7. Mount Enterprise API
    // (wrap metrics/notifications/lifecycle with adapters - see full_server example)
    // enterpriseAPI := web.NewEnterpriseAPI(iamEngine, nil, nil, nil, metricsAdapter, ...)
    // enterpriseAPI.RegisterRoutes(httpServer.App())

    // 8. Run
    httpServer.Start()
}
```

See [`examples/full_server/main.go`](examples/full_server/main.go) for the complete, working implementation including adapter wrappers.

### Storage class transitions

Objects start as `STANDARD` and can be transitioned through lifecycle rules:

```
STANDARD → STANDARD_IA → GLACIER → DEEP_ARCHIVE
   (hot)     (warm)       (cold)     (frozen)
```

Lifecycle rules are evaluated on a configurable interval (default: 24 hours).

### Object lock (WORM)

```go
lockMgr := velocity.NewObjectLockManager(db)

// Enable GOVERNANCE mode with 90-day retention
lockMgr.SetBucketLockConfig("my-bucket", velocity.ObjectLockConfig{
    Enabled: true,
    DefaultRetention: &velocity.RetentionConfig{
        Mode: velocity.LockModeGovernance,
        Days: 90,
    },
})

// Set legal hold on specific object
lockMgr.SetLegalHold("my-bucket/secret.pdf", true)
```

### Cluster setup (multi-node)

```go
clusterCfg := velocity.ClusterConfig{
    NodeID:      "node-1",
    BindAddress: "10.0.0.1:7946",
    Seeds:       []string{"10.0.0.2:7946", "10.0.0.3:7946"},
}
cluster := velocity.NewClusterManager(db, clusterCfg)
cluster.Start()
defer cluster.Stop()
```

---

## Library Usage (Go)

Velocity can be used as a pure Go library without the HTTP server:

```go
package main

import (
    "fmt"
    "github.com/oarkflow/velocity"
)

func main() {
    // Open database
    db, err := velocity.New("./mydb")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    // Key-value operations
    db.Put([]byte("greeting"), []byte("Hello, world!"))
    val, _ := db.Get([]byte("greeting"))
    fmt.Println(string(val)) // Hello, world!

    // Object storage
    meta, _ := db.StoreObject("photos/sunset.jpg", "image/jpeg", "alice",
        []byte("...image data..."), &velocity.ObjectOptions{
            Encrypt:      true,
            StorageClass: "STANDARD",
            Tags:         map[string]string{"project": "vacation"},
        })
    fmt.Println("Stored:", meta.Path, "Size:", meta.Size)

    // Retrieve object
    data, objMeta, _ := db.GetObject("photos/sunset.jpg", "alice")
    fmt.Println("Content-Type:", objMeta.ContentType, "Bytes:", len(data))

    // Bucket management
    bucketMgr := velocity.NewBucketManager(db)
    bucketMgr.CreateBucket("my-bucket", "admin", "us-east-1")

    // S3 credentials
    credStore := velocity.NewS3CredentialStore(db)
    cred, _ := credStore.GenerateCredentials("admin", "API access")
    fmt.Println("Access Key:", cred.AccessKeyID)
    fmt.Println("Secret Key:", cred.SecretAccessKey)

    // Erasure coding
    encoder := velocity.NewErasureEncoder(4, 2) // 4 data + 2 parity
    shards, _ := encoder.Encode([]byte("important data"))
    fmt.Println("Encoded into", len(shards), "shards")

    // Consistent hashing
    ring := velocity.NewConsistentHashRing(256)
    ring.AddNode("node-1")
    ring.AddNode("node-2")
    ring.AddNode("node-3")
    owner := ring.GetNode("photos/sunset.jpg")
    fmt.Println("Object owned by:", owner)

    // Metrics
    metrics := velocity.NewMetricsCollector()
    metrics.RecordRequest("GET", "200", 15*time.Millisecond)
    fmt.Println(metrics.RenderMetrics())
}
```

---

## License

See the project root for license details.

# object_storage

Demonstrates Velocity v2's object-storage surface (`api.ObjectService`):
buckets, versioning, `HeadObject`, `GetObjectRange` (partial reads),
`CopyObject`, and S3-style Object Lock retention (a `GOVERNANCE`-locked
object rejects deletion unless explicitly bypassed).

## Run

```sh
go run ./examples/object_storage
```

Uses a temp directory for storage, cleaned up automatically on exit. No
setup required.

## Expected output summary

Creates a bucket, writes two versions of the same object, reads back both
the latest and an explicit older version, lists/heads/range-reads the
object, copies it, then shows a retention-locked delete being rejected
and then succeeding once bypassed.

package api

import (
	"context"
	"io"
	"time"
)

// ObjectMeta describes one object version.
type ObjectMeta struct {
	Bucket      string
	Key         string
	VersionID   string
	Size        int64
	ContentType string
	ETag        string
	Tags        map[string]string
	CreatedAt   time.Time
}

// LockMode mirrors S3 Object Lock semantics: GOVERNANCE can be bypassed by
// a caller with the right permission, COMPLIANCE cannot be bypassed by
// anyone until RetainUntil passes.
type LockMode string

const (
	LockGovernance LockMode = "GOVERNANCE"
	LockCompliance LockMode = "COMPLIANCE"
)

// RetentionPolicy is applied per object version.
type RetentionPolicy struct {
	Mode        LockMode
	RetainUntil time.Time
	LegalHold   bool
}

// LifecycleRule drives background transition/expiry, evaluated by the
// object plugin's own scheduler.
type LifecycleRule struct {
	Prefix          string
	TransitionAfter time.Duration
	TransitionClass string
	ExpireAfter     time.Duration
}

// PartInfo identifies one uploaded part when completing a multipart
// upload. ETag must match the value UploadPart returned for that part —
// CompleteMultipart verifies this before assembling the final object.
type PartInfo struct {
	PartNumber int
	ETag       string
}

// ObjectService is the object-storage surface plugins/object exposes. It
// publishes TopicObjectPut / TopicObjectDelete on every mutation so
// observer plugins (compliance, replication, notifications) can react
// without object importing them.
type ObjectService interface {
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error

	PutObject(ctx context.Context, bucket, key string, r io.Reader, meta ObjectMeta) (ObjectMeta, error)
	// GetObject with versionID == "" returns the latest version.
	GetObject(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, ObjectMeta, error)
	// DeleteObject removes one version (versionID == "" deletes the
	// latest). bypassGovernance only has effect on LockGovernance objects;
	// it is always rejected for LockCompliance objects still under
	// retention or legal hold — that check belongs to the plugin, not the
	// caller.
	DeleteObject(ctx context.Context, bucket, key, versionID string, bypassGovernance bool) error
	ListObjects(ctx context.Context, bucket, prefix string) ([]ObjectMeta, error)

	PutRetention(ctx context.Context, bucket, key string, p RetentionPolicy) error
	SetLifecycle(ctx context.Context, bucket string, rules []LifecycleRule) error

	// HeadObject returns metadata only, without fetching the body.
	HeadObject(ctx context.Context, bucket, key, versionID string) (ObjectMeta, error)

	// GetObjectRange returns bytes [start, end] inclusive of the object
	// body (S3 Range semantics). end == -1 means "to EOF". The returned
	// ObjectMeta.Size is still the FULL object size, not the range
	// length — callers needing the range length should use the returned
	// reader's byte count (e.g. via io.Copy) or compute it from
	// start/end themselves, mirroring how S3 reports full object size in
	// most metadata fields alongside a separate Content-Range header.
	GetObjectRange(ctx context.Context, bucket, key, versionID string, start, end int64) (io.ReadCloser, ObjectMeta, error)

	// CopyObject duplicates srcBucket/srcKey (at srcVersionID, or latest
	// if empty) as a new version under dstBucket/dstKey.
	CopyObject(ctx context.Context, srcBucket, srcKey, srcVersionID, dstBucket, dstKey string) (ObjectMeta, error)

	// InitiateMultipart begins a multipart upload and returns an opaque
	// uploadID scoping subsequent UploadPart/CompleteMultipart/
	// AbortMultipart calls.
	InitiateMultipart(ctx context.Context, bucket, key string) (uploadID string, err error)
	// UploadPart stores one part's bytes and returns its ETag (a content
	// hash), which the caller must pass back in PartInfo on
	// CompleteMultipart.
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader) (etag string, err error)
	// CompleteMultipart verifies every part's ETag, assembles the parts
	// in PartInfo order into a single new object version, and discards
	// the part bookkeeping.
	CompleteMultipart(ctx context.Context, bucket, key, uploadID string, parts []PartInfo) (ObjectMeta, error)
	// AbortMultipart discards an in-progress multipart upload and any
	// parts already uploaded for it.
	AbortMultipart(ctx context.Context, bucket, key, uploadID string) error
}

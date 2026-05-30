package velocity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/oarkflow/velocity/pkg/s3"
)

const objectTagsPrefix = "obj:tags:"

func (db *DB) EncryptCredentialSecret(accessKeyID, secret string) (string, error) {
	if db.crypto == nil {
		return secret, nil
	}
	nonce, ciphertext, err := db.crypto.Encrypt([]byte(secret), []byte(accessKeyID))
	if err != nil {
		return "", err
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	return fmt.Sprintf("%x", sealed), nil
}

func (db *DB) DecryptCredentialSecret(accessKeyID, encrypted string) (string, error) {
	sealed, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	if len(sealed) < 24 {
		return "", fmt.Errorf("credential secret is malformed")
	}
	plain, err := db.crypto.Decrypt(sealed[:24], sealed[24:], []byte(accessKeyID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (db *DB) HasCredentialEncryption() bool {
	return db.crypto != nil
}

func (db *DB) ListObjectsForBucket(prefix string, maxKeys int) (int, error) {
	objects, err := db.ListObjects(ObjectListOptions{Prefix: prefix, MaxKeys: maxKeys})
	return len(objects), err
}

func (db *DB) MultipartPartsDir() string {
	return filepath.Join(db.path, "multipart")
}

func (db *DB) PutMultipartObject(ctx context.Context, req s3.MultipartPutObjectRequest) (*s3.MultipartObjectMetadata, error) {
	record, err := db.PutObject(ctx, PutObjectRequest{
		Bucket:        req.Bucket,
		Key:           req.Key,
		ContentType:   req.ContentType,
		User:          req.User,
		Reader:        req.Reader,
		Options:       &ObjectOptions{Version: req.Version, Encrypt: req.Encrypt || db.crypto != nil, StorageClass: req.StorageClass, CustomMetadata: req.Metadata},
		MultipartETag: req.MultipartETag,
		EnforceBucket: false,
	})
	if err != nil {
		return nil, err
	}
	meta := record.toMetadata()
	return &s3.MultipartObjectMetadata{Path: meta.Path, ETag: meta.ETag, Hash: meta.Hash, Size: meta.Size, LastModified: meta.ModifiedAt.UnixNano()}, nil
}

// CopyObject performs a server-side copy of an object
func (db *DB) CopyObject(srcBucket, srcKey, dstBucket, dstKey, user string) (*ObjectMetadata, error) {
	srcPath := srcBucket + "/" + srcKey

	// Get source object
	data, srcMeta, err := db.GetObject(srcPath, user)
	if err != nil {
		return nil, fmt.Errorf("source object not found: %w", err)
	}

	dstPath := dstBucket + "/" + dstKey

	// Store as new object
	opts := &ObjectOptions{
		Version:        DefaultVersion,
		Encrypt:        srcMeta.Encrypted,
		Tags:           srcMeta.Tags,
		CustomMetadata: srcMeta.CustomMetadata,
		StorageClass:   srcMeta.StorageClass,
	}

	meta, err := db.StoreObject(dstPath, srcMeta.ContentType, user, data, opts)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

// ObjectTagSet represents a set of tags on an object
type ObjectTagSet struct {
	Tags map[string]string `json:"tags"`
}

// PutObjectTagging sets tags on an object
func (db *DB) PutObjectTagging(bucket, key string, tags map[string]string) error {
	if len(tags) > 10 {
		return fmt.Errorf("too many tags: maximum 10 allowed")
	}

	for k, v := range tags {
		if len(k) > 128 {
			return fmt.Errorf("tag key too long: maximum 128 characters")
		}
		if len(v) > 256 {
			return fmt.Errorf("tag value too long: maximum 256 characters")
		}
	}

	tagSet := &ObjectTagSet{Tags: tags}
	data, err := json.Marshal(tagSet)
	if err != nil {
		return err
	}

	tagKey := objectTagsPrefix + bucket + "/" + key
	return db.PutWithTTL([]byte(tagKey), data, 0)
}

// GetObjectTagging retrieves tags for an object
func (db *DB) GetObjectTagging(bucket, key string) (map[string]string, error) {
	tagKey := objectTagsPrefix + bucket + "/" + key
	data, err := db.Get([]byte(tagKey))
	if err != nil {
		return map[string]string{}, nil // No tags is valid
	}

	var tagSet ObjectTagSet
	if err := json.Unmarshal(data, &tagSet); err != nil {
		return nil, err
	}

	if tagSet.Tags == nil {
		return map[string]string{}, nil
	}

	return tagSet.Tags, nil
}

// DeleteObjectTagging removes all tags from an object
func (db *DB) DeleteObjectTagging(bucket, key string) error {
	tagKey := objectTagsPrefix + bucket + "/" + key
	return db.Delete([]byte(tagKey))
}

// HeadObjectInfo returns metadata for HeadObject responses
type HeadObjectInfo struct {
	ContentType    string
	ContentLength  int64
	ETag           string
	LastModified   time.Time
	StorageClass   string
	VersionID      string
	Encrypted      bool
	CustomMetadata map[string]string
}

// GetHeadObjectInfo retrieves metadata suitable for HEAD responses
func (db *DB) GetHeadObjectInfo(bucket, key, user string) (*HeadObjectInfo, error) {
	path := bucket + "/" + key

	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return nil, err
	}

	// Check permissions
	if !db.hasPermissionInternal(path, user, PermissionRead, false) {
		return nil, ErrAccessDenied
	}

	etag := meta.ETag
	if etag == "" && meta.Hash != "" {
		etag = `"` + meta.Hash + `"`
	}

	return &HeadObjectInfo{
		ContentType:    meta.ContentType,
		ContentLength:  meta.Size,
		ETag:           etag,
		LastModified:   meta.ModifiedAt,
		StorageClass:   meta.StorageClass,
		VersionID:      meta.VersionID,
		Encrypted:      meta.Encrypted,
		CustomMetadata: meta.CustomMetadata,
	}, nil
}

// GetObjectWithRange retrieves an object with optional range support
func (db *DB) GetObjectWithRange(bucket, key, user, rangeHeader string) ([]byte, *ObjectMetadata, []s3.RangeSpec, error) {
	path := bucket + "/" + key
	data, meta, err := db.GetObject(path, user)
	if err != nil {
		return nil, nil, nil, err
	}

	if rangeHeader == "" {
		return data, meta, nil, nil
	}

	ranges, err := s3.ParseRangeHeader(rangeHeader, int64(len(data)))
	if err != nil {
		return nil, nil, nil, err
	}

	if len(ranges) == 1 {
		rangedData := s3.GetObjectRange(data, ranges[0])
		return rangedData, meta, ranges, nil
	}

	return data, meta, ranges, nil
}

// GetObjectStreamByBucketKey is a convenience wrapper
func (db *DB) GetObjectStreamByBucketKey(bucket, key, user string) (io.ReadCloser, *ObjectMetadata, error) {
	path := bucket + "/" + key
	return db.GetObjectStream(path, user)
}

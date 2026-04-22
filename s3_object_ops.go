package velocity

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// S3 Object Operations - Copy, Range reads, ETags, Conditional requests, Tagging

const (
	objectTagsPrefix = "obj:tags:"
)

// RangeSpec represents a parsed HTTP Range header
type RangeSpec struct {
	Start int64
	End   int64
}

// S3CopyResult holds the result of a copy operation (local type for s3_object_ops)
type S3CopyResult struct {
	ETag         string    `xml:"ETag"`
	LastModified time.Time `xml:"LastModified"`
}

// ParseRangeHeader parses an HTTP Range header like "bytes=0-499"
func ParseRangeHeader(rangeHeader string, objectSize int64) ([]RangeSpec, error) {
	if rangeHeader == "" {
		return nil, nil
	}

	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header")
	}

	rangeStr := strings.TrimPrefix(rangeHeader, "bytes=")
	var ranges []RangeSpec

	for _, part := range strings.Split(rangeStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		dashIdx := strings.IndexByte(part, '-')
		if dashIdx < 0 {
			return nil, fmt.Errorf("invalid range spec")
		}

		startStr := part[:dashIdx]
		endStr := part[dashIdx+1:]

		var r RangeSpec

		if startStr == "" {
			// Suffix range: -500 means last 500 bytes
			suffix, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range suffix")
			}
			r.Start = objectSize - suffix
			if r.Start < 0 {
				r.Start = 0
			}
			r.End = objectSize - 1
		} else if endStr == "" {
			// Open-ended range: 500- means from 500 to end
			start, err := strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start")
			}
			r.Start = start
			r.End = objectSize - 1
		} else {
			start, err := strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start")
			}
			end, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range end")
			}
			r.Start = start
			r.End = end
		}

		if r.Start > r.End || r.Start >= objectSize {
			return nil, fmt.Errorf("range not satisfiable")
		}

		if r.End >= objectSize {
			r.End = objectSize - 1
		}

		ranges = append(ranges, r)
	}

	return ranges, nil
}

// GetObjectRange returns a portion of the object data based on range spec
func GetObjectRange(data []byte, rangeSpec RangeSpec) []byte {
	if rangeSpec.Start >= int64(len(data)) {
		return nil
	}
	end := rangeSpec.End + 1
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return data[rangeSpec.Start:end]
}

// ComputeETag computes the ETag for an object (quoted MD5)
func ComputeETag(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
}

// ComputeMultipartETag computes the ETag for a multipart-uploaded object
func ComputeMultipartETag(partETags []string) string {
	combined := make([]byte, 0)
	for _, etag := range partETags {
		etag = strings.Trim(etag, `"`)
		hashBytes, _ := hex.DecodeString(etag)
		combined = append(combined, hashBytes...)
	}
	finalHash := md5.Sum(combined)
	return fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(finalHash[:]), len(partETags))
}

// ConditionalCheck evaluates conditional request headers
type ConditionalCheck struct {
	IfMatch           string
	IfNoneMatch       string
	IfModifiedSince   *time.Time
	IfUnmodifiedSince *time.Time
}

// EvaluateConditions checks conditional headers against object metadata
// Returns: (shouldContinue bool, statusCode int)
func EvaluateConditions(check ConditionalCheck, etag string, lastModified time.Time) (bool, int) {
	// If-Match: succeed only if ETag matches
	if check.IfMatch != "" {
		if check.IfMatch != "*" && check.IfMatch != etag {
			return false, 412 // Precondition Failed
		}
	}

	// If-None-Match: succeed only if ETag does NOT match
	if check.IfNoneMatch != "" {
		if check.IfNoneMatch == "*" || check.IfNoneMatch == etag {
			return false, 304 // Not Modified
		}
	}

	// If-Modified-Since: succeed only if object was modified after this date
	if check.IfModifiedSince != nil {
		if !lastModified.After(*check.IfModifiedSince) {
			return false, 304
		}
	}

	// If-Unmodified-Since: succeed only if object was NOT modified after this date
	if check.IfUnmodifiedSince != nil {
		if lastModified.After(*check.IfUnmodifiedSince) {
			return false, 412
		}
	}

	return true, 200
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

	// Compute ETag from stored data
	data, _, err := db.GetObject(path, user)
	etag := ""
	if err == nil {
		etag = ComputeETag(data)
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
func (db *DB) GetObjectWithRange(bucket, key, user, rangeHeader string) ([]byte, *ObjectMetadata, []RangeSpec, error) {
	path := bucket + "/" + key
	data, meta, err := db.GetObject(path, user)
	if err != nil {
		return nil, nil, nil, err
	}

	if rangeHeader == "" {
		return data, meta, nil, nil
	}

	ranges, err := ParseRangeHeader(rangeHeader, int64(len(data)))
	if err != nil {
		return nil, nil, nil, err
	}

	if len(ranges) == 1 {
		rangedData := GetObjectRange(data, ranges[0])
		return rangedData, meta, ranges, nil
	}

	// Multiple ranges - concatenate with boundaries
	var buf bytes.Buffer
	for _, r := range ranges {
		buf.Write(GetObjectRange(data, r))
	}

	return buf.Bytes(), meta, ranges, nil
}

// GetObjectStreamByBucketKey is a convenience wrapper
func (db *DB) GetObjectStreamByBucketKey(bucket, key, user string) (io.ReadCloser, *ObjectMetadata, error) {
	path := bucket + "/" + key
	return db.GetObjectStream(path, user)
}

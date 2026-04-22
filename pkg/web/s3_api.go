package web

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
)

// S3API provides S3-compatible HTTP API endpoints backed by the Velocity object store.
type S3API struct {
	db           *velocity.DB
	bucketMgr    *velocity.BucketManager
	multipartMgr *velocity.MultipartManager
	sigv4        *velocity.SigV4Auth
	presigned    *velocity.PresignedURLGenerator
}

// NewS3API creates a new S3API handler.
func NewS3API(
	db *velocity.DB,
	bucketMgr *velocity.BucketManager,
	multipartMgr *velocity.MultipartManager,
	sigv4 *velocity.SigV4Auth,
	presigned *velocity.PresignedURLGenerator,
) *S3API {
	return &S3API{
		db:           db,
		bucketMgr:    bucketMgr,
		multipartMgr: multipartMgr,
		sigv4:        sigv4,
		presigned:    presigned,
	}
}

// RegisterRoutes sets up S3-compatible routes on the given Fiber app.
// All routes are mounted under /s3 and protected by SigV4 auth middleware.
func (s *S3API) RegisterRoutes(app *fiber.App) {
	s3 := app.Group("/s3", s.s3AuthMiddleware())

	// Service-level: list all buckets
	s3.Get("/", s.handleListBuckets)

	// Bucket-level operations
	s3.Put("/:bucket", s.handleCreateBucket)
	s3.Delete("/:bucket", s.handleDeleteBucket)
	s3.Head("/:bucket", s.handleHeadBucket)
	// GET /:bucket routes to either ListObjectsV2 or other bucket-level ops
	s3.Get("/:bucket", s.handleBucketGet)

	// Object-level operations (key captured via wildcard)
	s3.Head("/:bucket/*", s.handleHeadObject)
	s3.Get("/:bucket/*", s.handleGetObject)
	s3.Put("/:bucket/*", s.handlePutObject)
	s3.Delete("/:bucket/*", s.handleDeleteObject)
	s3.Post("/:bucket/*", s.handlePostObject)
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

// s3AuthMiddleware validates SigV4 signatures on incoming requests.
func (s *S3API) s3AuthMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Convert Fiber's fasthttp request into a stdlib *http.Request for SigV4.
		stdReq, err := toStdHTTPRequest(c)
		if err != nil {
			return s.sendS3Error(c, velocity.S3ErrInternalError, "Failed to parse request", "", http.StatusInternalServerError)
		}

		cred, err := s.sigv4.VerifyRequest(stdReq)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "missing authentication") {
				return s.sendS3Error(c, velocity.S3ErrAccessDenied, "Missing authentication", "", http.StatusForbidden)
			}
			if strings.Contains(errMsg, "signature") || strings.Contains(errMsg, "Signature") {
				return s.sendS3Error(c, velocity.S3ErrSignatureDoesNotMatch, "Signature does not match", "", http.StatusForbidden)
			}
			if strings.Contains(errMsg, "invalid access key") {
				return s.sendS3Error(c, velocity.S3ErrInvalidAccessKeyId, "Invalid access key", "", http.StatusForbidden)
			}
			if strings.Contains(errMsg, "expired") {
				return s.sendS3Error(c, velocity.S3ErrExpiredToken, "Request has expired", "", http.StatusBadRequest)
			}
			return s.sendS3Error(c, velocity.S3ErrAccessDenied, errMsg, "", http.StatusForbidden)
		}

		// Store credential info for downstream handlers.
		c.Locals("s3credential", cred)
		c.Locals("s3user", cred.UserID)
		return c.Next()
	}
}

// ---------------------------------------------------------------------------
// Bucket operations
// ---------------------------------------------------------------------------

// handleListBuckets responds to GET /s3/ with an XML list of all buckets.
func (s *S3API) handleListBuckets(c fiber.Ctx) error {
	user := s3User(c)

	buckets, err := s.bucketMgr.ListBuckets(user)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), "/", http.StatusInternalServerError)
	}

	entries := make([]velocity.S3BucketEntry, 0, len(buckets))
	for _, b := range buckets {
		entries = append(entries, velocity.S3BucketEntry{
			Name:         b.Name,
			CreationDate: velocity.S3Time{Time: b.CreationDate},
		})
	}

	result := velocity.ListBucketsResult{
		Xmlns: velocity.S3XMLNamespace,
		Owner: velocity.S3Owner{
			ID:          user,
			DisplayName: user,
		},
		Buckets: velocity.S3BucketList{Bucket: entries},
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleCreateBucket responds to PUT /s3/:bucket.
func (s *S3API) handleCreateBucket(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	user := s3User(c)
	region := defaultRegion

	// Optionally parse CreateBucketConfiguration from body.
	body := c.Body()
	if len(body) > 0 {
		var cfg velocity.CreateBucketConfiguration
		if err := xml.Unmarshal(body, &cfg); err == nil && cfg.LocationConstraint != "" {
			region = cfg.LocationConstraint
		}
	}

	if err := s.bucketMgr.CreateBucket(bucket, user, region); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "BucketAlreadyExists") {
			return s.sendS3Error(c, velocity.S3ErrBucketAlreadyOwnedByYou, "Your previous request to create the named bucket succeeded and you already own it.", bucket, http.StatusConflict)
		}
		if strings.Contains(msg, "invalid") || strings.Contains(msg, "Invalid") {
			return s.sendS3Error(c, velocity.S3ErrInvalidBucketName, msg, bucket, http.StatusBadRequest)
		}
		return s.sendS3Error(c, velocity.S3ErrInternalError, msg, bucket, http.StatusInternalServerError)
	}

	c.Set("Location", "/"+bucket)
	return c.SendStatus(http.StatusOK)
}

// handleDeleteBucket responds to DELETE /s3/:bucket.
func (s *S3API) handleDeleteBucket(c fiber.Ctx) error {
	bucket := c.Params("bucket")

	if err := s.bucketMgr.DeleteBucket(bucket); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NoSuchBucket") {
			return s.sendS3Error(c, velocity.S3ErrNoSuchBucket, "The specified bucket does not exist", bucket, http.StatusNotFound)
		}
		if strings.Contains(msg, "BucketNotEmpty") {
			return s.sendS3Error(c, velocity.S3ErrBucketNotEmpty, "The bucket you tried to delete is not empty", bucket, http.StatusConflict)
		}
		return s.sendS3Error(c, velocity.S3ErrInternalError, msg, bucket, http.StatusInternalServerError)
	}

	return c.SendStatus(http.StatusNoContent)
}

// handleHeadBucket responds to HEAD /s3/:bucket.
func (s *S3API) handleHeadBucket(c fiber.Ctx) error {
	bucket := c.Params("bucket")

	info, err := s.bucketMgr.HeadBucket(bucket)
	if err != nil {
		return c.SendStatus(http.StatusNotFound)
	}

	c.Set("x-amz-bucket-region", info.Region)
	return c.SendStatus(http.StatusOK)
}

// handleBucketGet dispatches GET /s3/:bucket based on query parameters.
func (s *S3API) handleBucketGet(c fiber.Ctx) error {
	bucket := c.Params("bucket")

	// GET /?versioning => bucket versioning
	if c.Query("versioning") != "" || queryKeyExists(c, "versioning") {
		return s.handleGetBucketVersioning(c, bucket)
	}

	// GET /?uploads => list multipart uploads
	if c.Query("uploads") != "" || queryKeyExists(c, "uploads") {
		return s.handleListMultipartUploads(c, bucket)
	}

	// Default: ListObjectsV2
	return s.handleListObjectsV2(c, bucket)
}

// handleGetBucketVersioning returns versioning config for a bucket.
func (s *S3API) handleGetBucketVersioning(c fiber.Ctx, bucket string) error {
	state, err := s.bucketMgr.GetBucketVersioning(bucket)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), bucket, http.StatusInternalServerError)
	}

	result := velocity.VersioningConfiguration{
		Xmlns:  velocity.S3XMLNamespace,
		Status: state,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleListObjectsV2 implements GET /?list-type=2 (ListObjectsV2).
func (s *S3API) handleListObjectsV2(c fiber.Ctx, bucket string) error {
	// Verify bucket exists.
	if _, err := s.bucketMgr.HeadBucket(bucket); err != nil {
		return s.sendS3Error(c, velocity.S3ErrNoSuchBucket, "The specified bucket does not exist", bucket, http.StatusNotFound)
	}

	prefix := c.Query("prefix", "")
	delimiter := c.Query("delimiter", "")
	startAfter := c.Query("start-after", "")
	maxKeysStr := c.Query("max-keys", "1000")
	continuationToken := c.Query("continuation-token", "")

	maxKeys, err := strconv.Atoi(maxKeysStr)
	if err != nil || maxKeys < 0 {
		maxKeys = 1000
	}
	if maxKeys > 1000 {
		maxKeys = 1000
	}

	// Use continuation token as start-after if provided.
	if continuationToken != "" && startAfter == "" {
		startAfter = continuationToken
	}

	recursive := delimiter == ""

	opts := velocity.ObjectListOptions{
		Prefix:     bucket + "/" + prefix,
		MaxKeys:    maxKeys + 1, // fetch one extra to detect truncation
		StartAfter: func() string {
			if startAfter != "" {
				return bucket + "/" + startAfter
			}
			return ""
		}(),
		Recursive: recursive,
	}

	objects, err := s.db.ListObjects(opts)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), bucket, http.StatusInternalServerError)
	}

	isTruncated := len(objects) > maxKeys
	if isTruncated {
		objects = objects[:maxKeys]
	}

	// Build contents and common prefixes
	contents := make([]velocity.S3Object, 0, len(objects))
	commonPrefixes := make([]velocity.CommonPrefix, 0)
	seenPrefixes := make(map[string]bool)

	bucketPrefix := bucket + "/"
	for _, obj := range objects {
		// Strip bucket prefix from the key for the response.
		key := strings.TrimPrefix(obj.Path, bucketPrefix)
		if key == "" {
			continue
		}

		// If delimiter is set, handle common prefixes (virtual directories).
		if delimiter != "" {
			relKey := strings.TrimPrefix(key, prefix)
			if idx := strings.Index(relKey, delimiter); idx >= 0 {
				cp := prefix + relKey[:idx+len(delimiter)]
				if !seenPrefixes[cp] {
					seenPrefixes[cp] = true
					commonPrefixes = append(commonPrefixes, velocity.CommonPrefix{Prefix: cp})
				}
				continue
			}
		}

		etag := obj.Hash
		if etag == "" {
			etag = obj.Checksum
		}
		contents = append(contents, velocity.S3Object{
			Key:          key,
			LastModified: velocity.S3Time{Time: obj.ModifiedAt},
			ETag:         etag,
			Size:         obj.Size,
			StorageClass: obj.StorageClass,
		})
	}

	nextContinuationToken := ""
	if isTruncated && len(contents) > 0 {
		nextContinuationToken = contents[len(contents)-1].Key
	}

	result := velocity.ListObjectsV2Result{
		Xmlns:                 velocity.S3XMLNamespace,
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		KeyCount:              len(contents) + len(commonPrefixes),
		IsTruncated:           isTruncated,
		ContinuationToken:     continuationToken,
		NextContinuationToken: nextContinuationToken,
		StartAfter:            c.Query("start-after", ""),
		Contents:              contents,
		CommonPrefixes:        commonPrefixes,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleListMultipartUploads lists active multipart uploads for a bucket.
func (s *S3API) handleListMultipartUploads(c fiber.Ctx, bucket string) error {
	uploads, err := s.multipartMgr.ListMultipartUploads(bucket)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), bucket, http.StatusInternalServerError)
	}

	uploadInfos := make([]velocity.MultipartUploadInfo, 0, len(uploads))
	for _, u := range uploads {
		uploadInfos = append(uploadInfos, velocity.MultipartUploadInfo{
			Key:      u.Key,
			UploadId: u.UploadID,
			Initiator: velocity.S3Owner{
				ID:          u.Initiator,
				DisplayName: u.Initiator,
			},
			Owner: velocity.S3Owner{
				ID:          u.Initiator,
				DisplayName: u.Initiator,
			},
			StorageClass: u.StorageClass,
			Initiated:    velocity.S3Time{Time: u.CreatedAt},
		})
	}

	result := velocity.ListMultipartUploadsResult{
		Xmlns:      velocity.S3XMLNamespace,
		Bucket:     bucket,
		MaxUploads: 1000,
		Uploads:    uploadInfos,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Object operations
// ---------------------------------------------------------------------------

// handleGetObject responds to GET /s3/:bucket/* with range and conditional support.
func (s *S3API) handleGetObject(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	user := s3User(c)

	if key == "" {
		return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Object key is required", bucket, http.StatusBadRequest)
	}

	// Check for a specific version request.
	versionID := c.Query("versionId", "")

	// Get range header.
	rangeHeader := string(c.Request().Header.Peek("Range"))

	var data []byte
	var meta *velocity.ObjectMetadata
	var ranges []velocity.RangeSpec
	var err error

	if versionID != "" {
		// Fetch a specific version.
		data, meta, err = s.db.GetObjectVersion(bucket+"/"+key, versionID, user)
		if err != nil {
			return s.mapObjectError(c, err, bucket, key)
		}
		// Apply range if requested.
		if rangeHeader != "" {
			ranges, err = velocity.ParseRangeHeader(rangeHeader, int64(len(data)))
			if err != nil {
				return s.sendS3Error(c, velocity.S3ErrInvalidRange, err.Error(), bucket+"/"+key, http.StatusRequestedRangeNotSatisfiable)
			}
			if len(ranges) > 0 {
				data = velocity.GetObjectRange(data, ranges[0])
			}
		}
	} else {
		data, meta, ranges, err = s.db.GetObjectWithRange(bucket, key, user, rangeHeader)
		if err != nil {
			if strings.Contains(err.Error(), "range") || strings.Contains(err.Error(), "Range") {
				return s.sendS3Error(c, velocity.S3ErrInvalidRange, err.Error(), bucket+"/"+key, http.StatusRequestedRangeNotSatisfiable)
			}
			return s.mapObjectError(c, err, bucket, key)
		}
	}

	// Evaluate conditional headers.
	etag := velocity.ComputeETag(data)
	if meta != nil && meta.Hash != "" {
		etag = meta.Hash
	}
	lastModified := time.Now()
	if meta != nil {
		lastModified = meta.ModifiedAt
	}

	cond := velocity.ConditionalCheck{
		IfMatch:     c.Get("If-Match"),
		IfNoneMatch: c.Get("If-None-Match"),
	}
	if ims := c.Get("If-Modified-Since"); ims != "" {
		if t, err := time.Parse(http.TimeFormat, ims); err == nil {
			cond.IfModifiedSince = &t
		}
	}
	if ius := c.Get("If-Unmodified-Since"); ius != "" {
		if t, err := time.Parse(http.TimeFormat, ius); err == nil {
			cond.IfUnmodifiedSince = &t
		}
	}

	shouldContinue, condStatus := velocity.EvaluateConditions(cond, etag, lastModified)
	if !shouldContinue {
		return c.SendStatus(condStatus)
	}

	// Set response headers.
	if meta != nil {
		c.Set("Content-Type", meta.ContentType)
		c.Set("ETag", etag)
		c.Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if meta.VersionID != "" {
			c.Set("x-amz-version-id", meta.VersionID)
		}
		if meta.StorageClass != "" {
			c.Set("x-amz-storage-class", meta.StorageClass)
		}
		// Emit custom metadata as x-amz-meta-* headers.
		for k, v := range meta.CustomMetadata {
			c.Set("x-amz-meta-"+k, v)
		}
	}

	if ranges != nil && len(ranges) > 0 {
		r := ranges[0]
		totalSize := meta.Size
		c.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, totalSize))
		c.Set("Content-Length", strconv.Itoa(len(data)))
		return c.Status(http.StatusPartialContent).Send(data)
	}

	c.Set("Content-Length", strconv.Itoa(len(data)))
	return c.Status(http.StatusOK).Send(data)
}

// handlePutObject responds to PUT /s3/:bucket/* for object uploads and part uploads.
func (s *S3API) handlePutObject(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	user := s3User(c)

	if key == "" {
		return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Object key is required", bucket, http.StatusBadRequest)
	}

	// Check for multipart part upload: PUT ?partNumber=N&uploadId=ID
	partNumberStr := c.Query("partNumber", "")
	uploadID := c.Query("uploadId", "")
	if partNumberStr != "" && uploadID != "" {
		return s.handleUploadPart(c, bucket, key, uploadID, partNumberStr)
	}

	// Verify bucket exists.
	if _, err := s.bucketMgr.HeadBucket(bucket); err != nil {
		return s.sendS3Error(c, velocity.S3ErrNoSuchBucket, "The specified bucket does not exist", bucket, http.StatusNotFound)
	}

	// Check for copy source header.
	copySource := c.Get("x-amz-copy-source")
	if copySource != "" {
		return s.handleCopyObject(c, copySource, bucket, key, user)
	}

	// Read body.
	body := c.Body()

	contentType := c.Get("Content-Type", "application/octet-stream")
	storageClass := c.Get("x-amz-storage-class", velocity.S3StorageStandard)

	// Parse custom metadata from x-amz-meta-* headers.
	customMeta := make(map[string]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			customMeta[metaKey] = string(value)
		}
	})

	// Parse tags from x-amz-tagging header.
	tags := parseS3TaggingHeader(c.Get("x-amz-tagging"))

	path := bucket + "/" + key
	opts := &velocity.ObjectOptions{
		Encrypt:        true,
		StorageClass:   storageClass,
		Tags:           tags,
		CustomMetadata: customMeta,
	}

	meta, err := s.db.StoreObject(path, contentType, user, body, opts)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), path, http.StatusInternalServerError)
	}

	etag := velocity.ComputeETag(body)
	c.Set("ETag", etag)
	if meta.VersionID != "" {
		c.Set("x-amz-version-id", meta.VersionID)
	}

	return c.SendStatus(http.StatusOK)
}

// handleCopyObject performs a server-side copy.
func (s *S3API) handleCopyObject(c fiber.Ctx, copySource, dstBucket, dstKey, user string) error {
	// copySource format: /bucket/key or bucket/key
	copySource = strings.TrimPrefix(copySource, "/")
	parts := strings.SplitN(copySource, "/", 2)
	if len(parts) < 2 {
		return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Invalid copy source", copySource, http.StatusBadRequest)
	}
	srcBucket := parts[0]
	srcKey := parts[1]

	meta, err := s.db.CopyObject(srcBucket, srcKey, dstBucket, dstKey, user)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), copySource, http.StatusInternalServerError)
	}

	result := velocity.CopyObjectResult{
		LastModified: velocity.S3Time{Time: meta.ModifiedAt},
		ETag:         meta.Hash,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleDeleteObject responds to DELETE /s3/:bucket/*.
func (s *S3API) handleDeleteObject(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	user := s3User(c)

	if key == "" {
		return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Object key is required", bucket, http.StatusBadRequest)
	}

	// Check for multipart abort: DELETE ?uploadId=ID
	uploadID := c.Query("uploadId", "")
	if uploadID != "" {
		return s.handleAbortMultipartUpload(c, uploadID)
	}

	path := bucket + "/" + key
	err := s.db.DeleteObject(path, user)
	if err != nil {
		return s.mapObjectError(c, err, bucket, key)
	}

	return c.SendStatus(http.StatusNoContent)
}

// handleHeadObject responds to HEAD /s3/:bucket/*.
func (s *S3API) handleHeadObject(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	user := s3User(c)

	if key == "" {
		return c.SendStatus(http.StatusBadRequest)
	}

	info, err := s.db.GetHeadObjectInfo(bucket, key, user)
	if err != nil {
		if isNotFound(err) {
			return c.SendStatus(http.StatusNotFound)
		}
		if isAccessDenied(err) {
			return c.SendStatus(http.StatusForbidden)
		}
		return c.SendStatus(http.StatusInternalServerError)
	}

	c.Set("Content-Type", info.ContentType)
	c.Set("Content-Length", strconv.FormatInt(info.ContentLength, 10))
	c.Set("ETag", info.ETag)
	c.Set("Last-Modified", info.LastModified.UTC().Format(http.TimeFormat))
	if info.StorageClass != "" {
		c.Set("x-amz-storage-class", info.StorageClass)
	}
	if info.VersionID != "" {
		c.Set("x-amz-version-id", info.VersionID)
	}
	if info.Encrypted {
		c.Set("x-amz-server-side-encryption", "AES256")
	}
	for k, v := range info.CustomMetadata {
		c.Set("x-amz-meta-"+k, v)
	}

	return c.SendStatus(http.StatusOK)
}

// handlePostObject dispatches POST /s3/:bucket/* for multipart operations.
func (s *S3API) handlePostObject(c fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	// POST ?uploads => initiate multipart upload
	if queryKeyExists(c, "uploads") {
		return s.handleCreateMultipartUpload(c, bucket, key)
	}

	// POST ?uploadId=ID => complete multipart upload
	uploadID := c.Query("uploadId", "")
	if uploadID != "" {
		return s.handleCompleteMultipartUpload(c, bucket, key, uploadID)
	}

	return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Unsupported POST operation", bucket+"/"+key, http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// Multipart operations
// ---------------------------------------------------------------------------

// handleCreateMultipartUpload initiates a multipart upload.
func (s *S3API) handleCreateMultipartUpload(c fiber.Ctx, bucket, key string) error {
	user := s3User(c)
	contentType := c.Get("Content-Type", "application/octet-stream")

	// Parse custom metadata.
	metadata := make(map[string]string)
	c.Request().Header.VisitAll(func(k, v []byte) {
		ks := string(k)
		if strings.HasPrefix(strings.ToLower(ks), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(ks), "x-amz-meta-")
			metadata[metaKey] = string(v)
		}
	})

	upload, err := s.multipartMgr.CreateMultipartUpload(bucket, key, contentType, user, metadata)
	if err != nil {
		return s.sendS3Error(c, velocity.S3ErrInternalError, err.Error(), bucket+"/"+key, http.StatusInternalServerError)
	}

	result := velocity.InitiateMultipartUploadResult{
		Xmlns:    velocity.S3XMLNamespace,
		Bucket:   bucket,
		Key:      key,
		UploadId: upload.UploadID,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleUploadPart handles PUT ?partNumber=N&uploadId=ID.
func (s *S3API) handleUploadPart(c fiber.Ctx, bucket, key, uploadID, partNumberStr string) error {
	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > velocity.S3MaxPartCount {
		return s.sendS3Error(c, velocity.S3ErrInvalidArgument, "Invalid part number", bucket+"/"+key, http.StatusBadRequest)
	}

	body := c.Body()
	reader := bytes.NewReader(body)

	part, err := s.multipartMgr.UploadPart(uploadID, partNumber, reader, int64(len(body)))
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NoSuchUpload") {
			return s.sendS3Error(c, velocity.S3ErrNoSuchUpload, "The specified multipart upload does not exist", uploadID, http.StatusNotFound)
		}
		return s.sendS3Error(c, velocity.S3ErrInternalError, msg, uploadID, http.StatusInternalServerError)
	}

	c.Set("ETag", part.ETag)
	return c.SendStatus(http.StatusOK)
}

// handleCompleteMultipartUpload handles POST ?uploadId=ID.
func (s *S3API) handleCompleteMultipartUpload(c fiber.Ctx, bucket, key, uploadID string) error {
	body := c.Body()

	var completeReq velocity.CompletedMultipartUpload
	if err := xml.Unmarshal(body, &completeReq); err != nil {
		return s.sendS3Error(c, velocity.S3ErrMalformedXML, "The XML you provided was not well-formed", bucket+"/"+key, http.StatusBadRequest)
	}

	// Convert XML parts to the internal CompletePart type.
	parts := make([]velocity.CompletePart, len(completeReq.Parts))
	for i, p := range completeReq.Parts {
		parts[i] = velocity.CompletePart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	meta, err := s.multipartMgr.CompleteMultipartUpload(uploadID, parts)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NoSuchUpload") {
			return s.sendS3Error(c, velocity.S3ErrNoSuchUpload, "The specified multipart upload does not exist", uploadID, http.StatusNotFound)
		}
		if strings.Contains(msg, "InvalidPart") {
			return s.sendS3Error(c, velocity.S3ErrInvalidPart, msg, uploadID, http.StatusBadRequest)
		}
		return s.sendS3Error(c, velocity.S3ErrInternalError, msg, uploadID, http.StatusInternalServerError)
	}

	result := velocity.CompleteMultipartUploadResult{
		Xmlns:    velocity.S3XMLNamespace,
		Location: fmt.Sprintf("/s3/%s/%s", bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     meta.Hash,
	}

	return s.sendXML(c, http.StatusOK, result)
}

// handleAbortMultipartUpload handles DELETE ?uploadId=ID.
func (s *S3API) handleAbortMultipartUpload(c fiber.Ctx, uploadID string) error {
	err := s.multipartMgr.AbortMultipartUpload(uploadID)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NoSuchUpload") {
			return s.sendS3Error(c, velocity.S3ErrNoSuchUpload, "The specified multipart upload does not exist", uploadID, http.StatusNotFound)
		}
		return s.sendS3Error(c, velocity.S3ErrInternalError, msg, uploadID, http.StatusInternalServerError)
	}

	return c.SendStatus(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// XML / error helpers
// ---------------------------------------------------------------------------

const defaultRegion = "us-east-1"

// sendXML marshals v as XML and sends it with the given status code.
func (s *S3API) sendXML(c fiber.Ctx, status int, v interface{}) error {
	xmlBytes, err := xml.Marshal(v)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("XML marshal error")
	}

	c.Set("Content-Type", "application/xml")
	return c.Status(status).Send(append([]byte(xml.Header), xmlBytes...))
}

// sendS3Error sends an S3-compatible XML error response.
func (s *S3API) sendS3Error(c fiber.Ctx, code, message, resource string, httpStatus int) error {
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())
	s3err := velocity.NewS3Error(code, message, resource, requestID)

	xmlBytes, err := xml.Marshal(s3err)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("XML marshal error")
	}

	c.Set("Content-Type", "application/xml")
	return c.Status(httpStatus).Send(append([]byte(xml.Header), xmlBytes...))
}

// mapObjectError translates common velocity errors into S3 XML errors.
func (s *S3API) mapObjectError(c fiber.Ctx, err error, bucket, key string) error {
	resource := bucket + "/" + key
	msg := err.Error()

	if isNotFound(err) {
		return s.sendS3Error(c, velocity.S3ErrNoSuchKey, "The specified key does not exist.", resource, http.StatusNotFound)
	}
	if isAccessDenied(err) {
		return s.sendS3Error(c, velocity.S3ErrAccessDenied, "Access Denied", resource, http.StatusForbidden)
	}
	if strings.Contains(msg, "InvalidVersion") || strings.Contains(msg, "invalid version") {
		return s.sendS3Error(c, velocity.S3ErrNoSuchVersion, "The specified version does not exist.", resource, http.StatusNotFound)
	}

	return s.sendS3Error(c, velocity.S3ErrInternalError, msg, resource, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// s3User extracts the authenticated user ID from context.
func s3User(c fiber.Ctx) string {
	if user, ok := c.Locals("s3user").(string); ok && user != "" {
		return user
	}
	return "anonymous"
}

// queryKeyExists checks whether a query parameter key is present (even if empty).
func queryKeyExists(c fiber.Ctx, key string) bool {
	return strings.Contains(string(c.Request().URI().QueryString()), key)
}

// parseS3TaggingHeader parses the x-amz-tagging header (URL-encoded key=value pairs).
func parseS3TaggingHeader(header string) map[string]string {
	tags := make(map[string]string)
	if header == "" {
		return tags
	}

	for _, pair := range strings.Split(header, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			tags[kv[0]] = kv[1]
		}
	}
	return tags
}

// toStdHTTPRequest builds a minimal stdlib *http.Request from a Fiber context.
// This is necessary because SigV4Auth.VerifyRequest expects *http.Request.
func toStdHTTPRequest(c fiber.Ctx) (*http.Request, error) {
	uri := c.Request().URI()

	u := fmt.Sprintf("%s://%s%s",
		string(uri.Scheme()),
		string(uri.Host()),
		string(uri.RequestURI()),
	)
	if string(uri.Scheme()) == "" {
		u = fmt.Sprintf("http://%s%s", string(c.Request().Header.Host()), string(uri.RequestURI()))
	}

	body := c.Body()
	req, err := http.NewRequest(c.Method(), u, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, err
	}

	// Copy all headers.
	c.Request().Header.VisitAll(func(key, value []byte) {
		req.Header.Set(string(key), string(value))
	})

	req.Host = string(c.Request().Header.Host())
	return req, nil
}

// isNotFound checks if an error indicates a not-found condition.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if err == velocity.ErrObjectNotFound {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "NotFound") || strings.Contains(msg, "NoSuchKey")
}

// isAccessDenied checks if an error indicates an access-denied condition.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if err == velocity.ErrAccessDenied {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "access denied") || strings.Contains(msg, "AccessDenied")
}

package s3

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	multipartPrefix     = "multipart:upload:"
	multipartPartPrefix = "multipart:part:"
	minPartSize         = 5 * 1024 * 1024 // 5MB minimum (except last part)
	maxPartNumber       = 10000
)

// MultipartUpload represents an in-progress multipart upload
type MultipartUpload struct {
	UploadID     string            `json:"upload_id"`
	Bucket       string            `json:"bucket"`
	Key          string            `json:"key"`
	ContentType  string            `json:"content_type"`
	Initiator    string            `json:"initiator"`
	StorageClass string            `json:"storage_class"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// MultipartPart represents a single part in a multipart upload
type MultipartPart struct {
	PartNumber   int       `json:"part_number" xml:"PartNumber"`
	ETag         string    `json:"etag" xml:"ETag"`
	Size         int64     `json:"size" xml:"Size"`
	LastModified time.Time `json:"last_modified" xml:"LastModified"`
}

// CompletePart represents a part in the complete multipart upload request
type CompletePart struct {
	PartNumber int    `json:"PartNumber" xml:"PartNumber"`
	ETag       string `json:"ETag" xml:"ETag"`
}

// MultipartManager manages multipart uploads
type MultipartManager struct {
	store    MultipartStore
	partsDir string
}

// NewMultipartManager creates a new multipart manager
func NewMultipartManager(store MultipartStore) *MultipartManager {
	partsDir := store.MultipartPartsDir()
	os.MkdirAll(partsDir, 0700)

	return &MultipartManager{
		store:    store,
		partsDir: partsDir,
	}
}

// CreateMultipartUpload initiates a new multipart upload
func (mm *MultipartManager) CreateMultipartUpload(bucket, key, contentType, user string, metadata map[string]string) (*MultipartUpload, error) {
	uploadID, err := generateMultipartUploadID()
	if err != nil {
		return nil, err
	}

	upload := &MultipartUpload{
		UploadID:     uploadID,
		Bucket:       bucket,
		Key:          key,
		ContentType:  contentType,
		Initiator:    user,
		StorageClass: "STANDARD",
		Metadata:     metadata,
		CreatedAt:    time.Now().UTC(),
	}

	data, err := json.Marshal(upload)
	if err != nil {
		return nil, err
	}

	uploadKey := fmt.Sprintf("%s%s/%s/%s", multipartPrefix, bucket, key, uploadID)
	if err := mm.store.PutWithTTL([]byte(uploadKey), data, 0); err != nil {
		return nil, err
	}

	// Create directory for parts
	uploadDir := filepath.Join(mm.partsDir, uploadID)
	if err := os.MkdirAll(uploadDir, 0700); err != nil {
		return nil, err
	}

	return upload, nil
}

// UploadPart uploads a single part
func (mm *MultipartManager) UploadPart(uploadID string, partNumber int, data io.Reader, size int64) (*MultipartPart, error) {
	if partNumber < 1 || partNumber > maxPartNumber {
		return nil, fmt.Errorf("invalid part number: must be between 1 and %d", maxPartNumber)
	}

	// Verify upload exists
	upload, err := mm.getUpload(uploadID)
	if err != nil {
		return nil, fmt.Errorf("NoSuchUpload")
	}

	// Write part to disk
	partPath := filepath.Join(mm.partsDir, uploadID, fmt.Sprintf("%05d", partNumber))
	f, err := os.Create(partPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Compute MD5 while writing
	hash := md5.New()
	written, err := io.Copy(io.MultiWriter(f, hash), data)
	if err != nil {
		os.Remove(partPath)
		return nil, err
	}

	etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash.Sum(nil)))

	part := &MultipartPart{
		PartNumber:   partNumber,
		ETag:         etag,
		Size:         written,
		LastModified: time.Now().UTC(),
	}

	// Store part metadata
	partKey := fmt.Sprintf("%s%s/%05d", multipartPartPrefix, uploadID, partNumber)
	partData, err := json.Marshal(part)
	if err != nil {
		return nil, err
	}

	if err := mm.store.PutWithTTL([]byte(partKey), partData, 0); err != nil {
		return nil, err
	}

	_ = upload // verified above
	return part, nil
}

// CompleteMultipartUpload assembles parts into the final object
func (mm *MultipartManager) CompleteMultipartUpload(uploadID string, parts []CompletePart) (*MultipartObjectMetadata, error) {
	upload, err := mm.getUpload(uploadID)
	if err != nil {
		return nil, fmt.Errorf("NoSuchUpload")
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("InvalidRequest: no parts specified")
	}

	// Sort parts by part number
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	// Validate parts and compute combined ETag
	md5Hashes := make([]byte, 0)
	storedParts, err := mm.ListParts(uploadID)
	if err != nil {
		return nil, err
	}
	partByNumber := make(map[int]MultipartPart, len(storedParts))
	for _, part := range storedParts {
		partByNumber[part.PartNumber] = part
	}
	tmp, err := os.CreateTemp(mm.partsDir, "complete-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpName) }()

	seen := make(map[int]struct{}, len(parts))
	for i, cp := range parts {
		if _, exists := seen[cp.PartNumber]; exists {
			return nil, fmt.Errorf("InvalidPartOrder: duplicate part %d", cp.PartNumber)
		}
		seen[cp.PartNumber] = struct{}{}
		stored, ok := partByNumber[cp.PartNumber]
		if !ok {
			return nil, fmt.Errorf("InvalidPart: part %d not found", cp.PartNumber)
		}
		if strings.Trim(cp.ETag, `"`) != strings.Trim(stored.ETag, `"`) {
			return nil, fmt.Errorf("InvalidPart: ETag mismatch for part %d", cp.PartNumber)
		}
		if multipartStrict(upload) && i < len(parts)-1 && stored.Size < minPartSize {
			return nil, fmt.Errorf("EntityTooSmall: part %d is smaller than %d bytes", cp.PartNumber, minPartSize)
		}
		partPath := filepath.Join(mm.partsDir, uploadID, fmt.Sprintf("%05d", cp.PartNumber))
		partFile, err := os.Open(partPath)
		if err != nil {
			return nil, fmt.Errorf("InvalidPart: part %d not found", cp.PartNumber)
		}

		_, err = io.Copy(tmp, partFile)
		partFile.Close()
		if err != nil {
			return nil, err
		}

		// Parse ETag for MD5 hash
		etag := strings.Trim(stored.ETag, `"`)
		hashBytes, _ := hex.DecodeString(etag)
		md5Hashes = append(md5Hashes, hashBytes...)
	}

	// Compute combined ETag: MD5 of concatenated part MD5s, with -N suffix
	combinedHash := md5.Sum(md5Hashes)
	combinedETag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(combinedHash[:]), len(parts))
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	record, err := mm.store.PutMultipartObject(context.Background(), MultipartPutObjectRequest{
		Bucket:        upload.Bucket,
		Key:           upload.Key,
		ContentType:   upload.ContentType,
		User:          upload.Initiator,
		Reader:        tmp,
		Version:       "v1",
		Encrypt:       false,
		StorageClass:  upload.StorageClass,
		Metadata:      upload.Metadata,
		MultipartETag: combinedETag,
	})
	if err != nil {
		return nil, err
	}

	// Cleanup
	mm.cleanupUpload(uploadID)

	return record, nil
}

func multipartStrict(upload *MultipartUpload) bool {
	if upload == nil || upload.Metadata == nil {
		return false
	}
	return strings.EqualFold(upload.Metadata["strict_s3_multipart"], "true")
}

// AbortMultipartUpload cancels a multipart upload and cleans up parts
func (mm *MultipartManager) AbortMultipartUpload(uploadID string) error {
	_, err := mm.getUpload(uploadID)
	if err != nil {
		return fmt.Errorf("NoSuchUpload")
	}

	mm.cleanupUpload(uploadID)
	return nil
}

// ListMultipartUploads lists active multipart uploads for a bucket
func (mm *MultipartManager) ListMultipartUploads(bucket string) ([]MultipartUpload, error) {
	prefix := multipartPrefix + bucket + "/"
	keys, err := mm.store.Keys(prefix + "*")
	if err != nil {
		return nil, err
	}

	var uploads []MultipartUpload
	for _, key := range keys {
		data, err := mm.store.Get([]byte(key))
		if err != nil {
			continue
		}

		var upload MultipartUpload
		if err := json.Unmarshal(data, &upload); err != nil {
			continue
		}

		uploads = append(uploads, upload)
	}

	return uploads, nil
}

// ListParts lists parts for a multipart upload
func (mm *MultipartManager) ListParts(uploadID string) ([]MultipartPart, error) {
	prefix := multipartPartPrefix + uploadID + "/"
	keys, err := mm.store.Keys(prefix + "*")
	if err != nil {
		return nil, err
	}

	var parts []MultipartPart
	for _, key := range keys {
		data, err := mm.store.Get([]byte(key))
		if err != nil {
			continue
		}

		var part MultipartPart
		if err := json.Unmarshal(data, &part); err != nil {
			continue
		}

		parts = append(parts, part)
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	return parts, nil
}

func (mm *MultipartManager) getUpload(uploadID string) (*MultipartUpload, error) {
	keys, err := mm.store.Keys(multipartPrefix + "*/" + uploadID)
	if err != nil || len(keys) == 0 {
		// Try with wildcard pattern
		allKeys, err := mm.store.Keys(multipartPrefix + "*")
		if err != nil {
			return nil, fmt.Errorf("upload not found")
		}

		for _, k := range allKeys {
			if strings.HasSuffix(k, "/"+uploadID) {
				data, err := mm.store.Get([]byte(k))
				if err != nil {
					continue
				}
				var upload MultipartUpload
				if err := json.Unmarshal(data, &upload); err != nil {
					continue
				}
				return &upload, nil
			}
		}
		return nil, fmt.Errorf("upload not found")
	}

	data, err := mm.store.Get([]byte(keys[0]))
	if err != nil {
		return nil, err
	}

	var upload MultipartUpload
	if err := json.Unmarshal(data, &upload); err != nil {
		return nil, err
	}

	return &upload, nil
}

func (mm *MultipartManager) cleanupUpload(uploadID string) {
	// Remove parts directory
	os.RemoveAll(filepath.Join(mm.partsDir, uploadID))

	// Remove upload metadata
	keys, _ := mm.store.Keys(multipartPrefix + "*/" + uploadID)
	for _, k := range keys {
		mm.store.Delete([]byte(k))
	}

	// Remove part metadata
	partKeys, _ := mm.store.Keys(multipartPartPrefix + uploadID + "/*")
	for _, k := range partKeys {
		mm.store.Delete([]byte(k))
	}
}

func generateMultipartUploadID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

package velocity

import (
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
	multipartPrefix    = "multipart:upload:"
	multipartPartPrefix = "multipart:part:"
	minPartSize        = 5 * 1024 * 1024 // 5MB minimum (except last part)
	maxPartNumber      = 10000
)

// MultipartUpload represents an in-progress multipart upload
type MultipartUpload struct {
	UploadID    string            `json:"upload_id"`
	Bucket      string            `json:"bucket"`
	Key         string            `json:"key"`
	ContentType string            `json:"content_type"`
	Initiator   string            `json:"initiator"`
	StorageClass string           `json:"storage_class"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
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
	db       *DB
	partsDir string
}

// NewMultipartManager creates a new multipart manager
func NewMultipartManager(db *DB) *MultipartManager {
	partsDir := filepath.Join(db.path, "multipart")
	os.MkdirAll(partsDir, 0700)

	return &MultipartManager{
		db:       db,
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
	if err := mm.db.PutWithTTL([]byte(uploadKey), data, 0); err != nil {
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

	if err := mm.db.PutWithTTL([]byte(partKey), partData, 0); err != nil {
		return nil, err
	}

	_ = upload // verified above
	return part, nil
}

// CompleteMultipartUpload assembles parts into the final object
func (mm *MultipartManager) CompleteMultipartUpload(uploadID string, parts []CompletePart) (*ObjectMetadata, error) {
	upload, err := mm.getUpload(uploadID)
	if err != nil {
		return nil, fmt.Errorf("NoSuchUpload")
	}

	// Sort parts by part number
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	// Validate parts and compute combined ETag
	var totalSize int64
	md5Hashes := make([]byte, 0)

	objectsDir := filepath.Join(mm.db.filesDir, "objects")
	objectID := generateObjectID()
	versionID := generateVersionID()
	finalDir := filepath.Join(objectsDir, objectID)
	if err := os.MkdirAll(finalDir, 0700); err != nil {
		return nil, err
	}

	finalPath := filepath.Join(finalDir, versionID)
	outFile, err := os.Create(finalPath)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	for _, cp := range parts {
		partPath := filepath.Join(mm.partsDir, uploadID, fmt.Sprintf("%05d", cp.PartNumber))
		partFile, err := os.Open(partPath)
		if err != nil {
			os.Remove(finalPath)
			return nil, fmt.Errorf("InvalidPart: part %d not found", cp.PartNumber)
		}

		n, err := io.Copy(outFile, partFile)
		partFile.Close()
		if err != nil {
			os.Remove(finalPath)
			return nil, err
		}

		totalSize += n

		// Parse ETag for MD5 hash
		etag := strings.Trim(cp.ETag, `"`)
		hashBytes, _ := hex.DecodeString(etag)
		md5Hashes = append(md5Hashes, hashBytes...)
	}

	// Compute combined ETag: MD5 of concatenated part MD5s, with -N suffix
	combinedHash := md5.Sum(md5Hashes)
	combinedETag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(combinedHash[:]), len(parts))

	now := time.Now().UTC()
	path := upload.Bucket + "/" + upload.Key

	meta := &ObjectMetadata{
		ObjectID:       objectID,
		Path:           path,
		Folder:         upload.Bucket,
		Name:           upload.Key,
		ContentType:    upload.ContentType,
		Size:           totalSize,
		Hash:           combinedETag,
		Encrypted:      false,
		Version:        DefaultVersion,
		VersionID:      versionID,
		IsLatest:       true,
		CreatedAt:      now,
		ModifiedAt:     now,
		CreatedBy:      upload.Initiator,
		ModifiedBy:     upload.Initiator,
		Checksum:       combinedETag,
		StorageClass:   upload.StorageClass,
		CustomMetadata: upload.Metadata,
	}

	// Save metadata
	if err := mm.db.saveObjectMetadata(meta); err != nil {
		os.Remove(finalPath)
		return nil, err
	}

	// Save version
	version := &ObjectVersion{
		VersionID: versionID,
		ObjectID:  objectID,
		Size:      totalSize,
		Hash:      combinedETag,
		CreatedAt: now,
		CreatedBy: upload.Initiator,
		IsLatest:  true,
	}
	mm.db.saveObjectVersion(path, version)

	// Index
	mm.db.indexObject(path, objectID)

	// Cleanup
	mm.cleanupUpload(uploadID)

	return meta, nil
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
	keys, err := mm.db.Keys(prefix + "*")
	if err != nil {
		return nil, err
	}

	var uploads []MultipartUpload
	for _, key := range keys {
		data, err := mm.db.Get([]byte(key))
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
	keys, err := mm.db.Keys(prefix + "*")
	if err != nil {
		return nil, err
	}

	var parts []MultipartPart
	for _, key := range keys {
		data, err := mm.db.Get([]byte(key))
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
	keys, err := mm.db.Keys(multipartPrefix + "*/" + uploadID)
	if err != nil || len(keys) == 0 {
		// Try with wildcard pattern
		allKeys, err := mm.db.Keys(multipartPrefix + "*")
		if err != nil {
			return nil, fmt.Errorf("upload not found")
		}

		for _, k := range allKeys {
			if strings.HasSuffix(k, "/"+uploadID) {
				data, err := mm.db.Get([]byte(k))
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

	data, err := mm.db.Get([]byte(keys[0]))
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
	keys, _ := mm.db.Keys(multipartPrefix + "*/" + uploadID)
	for _, k := range keys {
		mm.db.Delete([]byte(k))
	}

	// Remove part metadata
	partKeys, _ := mm.db.Keys(multipartPartPrefix + uploadID + "/*")
	for _, k := range partKeys {
		mm.db.Delete([]byte(k))
	}
}

func generateMultipartUploadID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

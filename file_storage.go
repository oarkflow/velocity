package velocity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/image/draw"
)

const (
	fileDataPrefix  = "file:data:"
	fileMetaPrefix  = "file:meta:"
	fileThumbPrefix = "file:thumb:"
)

var (
	ErrFileNotFound = errors.New("file not found")
	ErrFileExists   = errors.New("file already exists")
)

type FileMetadata struct {
	Key             string    `json:"key"`
	Filename        string    `json:"filename"`
	ContentType     string    `json:"content_type"`
	Size            int64     `json:"size"`
	UploadedAt      time.Time `json:"uploaded_at"`
	ThumbnailWidth  int       `json:"thumbnail_width,omitempty"`
	ThumbnailHeight int       `json:"thumbnail_height,omitempty"`
	ThumbnailURL    string    `json:"thumbnail_url,omitempty"`
}

func (db *DB) StoreFile(key, filename, contentType string, data []byte) (*FileMetadata, error) {
	// default to streaming storage when configured
	return db.StoreFileStream(key, filename, contentType, bytes.NewReader(data), int64(len(data)))
}

// StoreFileStream stores the provided reader's content in a stream-safe manner without loading all of it into memory.
// When DB is configured with UseFileStorage=true, file bytes are stored on disk under db.filesDir and metadata stored in DB.
func (db *DB) StoreFileStream(key, filename, contentType string, r io.Reader, size int64) (*FileMetadata, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename is required")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if key == "" {
		key = generateFileKey()
	}
	if db.HasFile(key) {
		return nil, ErrFileExists
	}

	// Ensure filesDir exists
	if db.filesDir == "" {
		db.filesDir = filepath.Join(db.path, "files")
		os.MkdirAll(db.filesDir, 0755)
	}

	tmp, err := os.CreateTemp(db.filesDir, "upload-*.tmp")
	if err != nil {
		return nil, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()

	// copy from reader into tmp (size may be -1 if unknown)
	written, err := io.Copy(tmp, io.LimitReader(r, db.maxUploadSize+1))
	if err != nil {
		return nil, err
	}
	if written > db.maxUploadSize {
		return nil, fmt.Errorf("uploaded file too large")
	}

	// Compute checksum and finalize
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// For backward compatibility, store metadata in DB and file on disk
	meta := &FileMetadata{
		Key:         key,
		Filename:    filename,
		ContentType: contentType,
		Size:        written,
		UploadedAt:  time.Now().UTC(),
	}

	// Move tmp to final path
	finalPath := filepath.Join(db.filesDir, key)
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), finalPath); err != nil {
		return nil, err
	}

	// Store metadata in DB
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	metaKey := []byte(fileMetaPrefix + key)
	if err := db.Put(metaKey, metaBytes); err != nil {
		// rollback file
		_ = os.Remove(finalPath)
		return nil, err
	}

	// If image, kick off thumbnail generation asynchronously to avoid blocking
	if strings.HasPrefix(contentType, "image/") {
		go func(k string) {
			if _, _, _, _, err := db.GenerateThumbnail(k, 200); err != nil {
				log.Printf("thumbnail generation failed for %s: %v", k, err)
			}
		}(key)
	}

	// Read metadata back for return
	return meta, nil
}

func (db *DB) GetFile(key string) ([]byte, *FileMetadata, error) {
	// Prefer filesystem storage if present
	meta, err := db.GetFileMetadata(key)
	if err != nil {
		return nil, nil, err
	}
	if db.filesDir != "" {
		path := filepath.Join(db.filesDir, key)
		if _, err := os.Stat(path); err == nil {
			b, err := os.ReadFile(path)
			if err == nil {
				return b, meta, nil
			}
		}
	}

	// Fallback to legacy in-DB storage
	dataKey := []byte(fileDataPrefix + key)
	data, err := db.Get(dataKey)
	if err != nil {
		return nil, nil, translateFileError(err)
	}
	return data, meta, nil
}

func (db *DB) DeleteFile(key string) error {
	if _, err := db.GetFileMetadata(key); err != nil {
		return err
	}

	// remove on-disk file if present
	if db.filesDir != "" {
		p := filepath.Join(db.filesDir, key)
		_ = os.Remove(p)
	}

	metaKey := []byte(fileMetaPrefix + key)
	dataKey := []byte(fileDataPrefix + key)
	_ = db.Delete(dataKey) // best-effort, ignore error if legacy blob missing
	if err := db.Delete(metaKey); err != nil {
		return err
	}
	return nil
}

func (db *DB) ListFiles() ([]FileMetadata, error) {
	files := make([]FileMetadata, 0)
	// Use paginated key listing to avoid materializing all keys
	offset := 0
	limit := 100
	for {
		keys, _ := db.KeysPage(offset, limit)
		if len(keys) == 0 {
			break
		}
		for _, key := range keys {
			keyStr := string(key)
			if strings.HasPrefix(keyStr, fileMetaPrefix) {
				raw, err := db.Get(key)
				if err != nil {
					if errors.Is(translateFileError(err), ErrFileNotFound) {
						continue
					}
					return nil, err
				}
				var meta FileMetadata
				if err := json.Unmarshal(raw, &meta); err != nil {
					return nil, err
				}
				files = append(files, meta)
			}
		}
		if len(keys) < limit {
			break
		}
		offset += limit
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadedAt.After(files[j].UploadedAt)
	})

	return files, nil
}

func (db *DB) HasFile(key string) bool {
	return db.Has([]byte(fileMetaPrefix + key))
}

// GetThumbnail returns the cached thumbnail for a file (generates it if missing)
func (db *DB) GetThumbnail(key string) ([]byte, string, int, int, error) {
	if !db.HasFile(key) {
		return nil, "", 0, 0, ErrFileNotFound
	}
	thumbKey := []byte(fileThumbPrefix + key)
	if db.Has(thumbKey) {
		b, err := db.Get(thumbKey)
		if err != nil {
			return nil, "", 0, 0, err
		}
		// try to get metadata for dimensions
		meta, err := db.GetFileMetadata(key)
		if err == nil {
			return b, "image/jpeg", meta.ThumbnailWidth, meta.ThumbnailHeight, nil
		}
		return b, "image/jpeg", 0, 0, nil
	}
	// generate on demand
	b, ct, w, h, err := db.GenerateThumbnail(key, 200)
	if err != nil {
		return nil, "", 0, 0, err
	}
	return b, ct, w, h, nil
}

// GenerateThumbnail creates and stores a JPEG thumbnail for an image file
func (db *DB) GenerateThumbnail(key string, maxDim int) ([]byte, string, int, int, error) {
	data, meta, err := db.GetFile(key)
	if err != nil {
		return nil, "", 0, 0, err
	}
	if !strings.HasPrefix(meta.ContentType, "image/") {
		return nil, "", 0, 0, fmt.Errorf("not an image")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", 0, 0, err
	}
	// compute size
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	var nw, nh int
	if w > h {
		if w <= maxDim {
			nw = w
			nh = h
		} else {
			nw = maxDim
			nh = int(float64(h) * float64(maxDim) / float64(w))
		}
	} else {
		if h <= maxDim {
			nw = w
			nh = h
		} else {
			nh = maxDim
			nw = int(float64(w) * float64(maxDim) / float64(h))
		}
	}
	thumb := image.NewRGBA(image.Rect(0, 0, nw, nh))
	// use golang.org/x/image/draw for resize
	draw.ApproxBiLinear.Scale(thumb, thumb.Bounds(), img, img.Bounds(), draw.Over, nil)
	// encode to jpeg
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumb, &jpeg.Options{Quality: 80}); err != nil {
		return nil, "", 0, 0, err
	}
	thumbBytes := buf.Bytes()
	// store thumb
	if err := db.Put([]byte(fileThumbPrefix+key), thumbBytes); err != nil {
		return nil, "", 0, 0, err
	}
	// update metadata with dimensions and thumbnail url
	meta.ThumbnailWidth = nw
	meta.ThumbnailHeight = nh
	meta.ThumbnailURL = "/api/files/" + key + "/thumbnail"
	metaBytes, _ := json.Marshal(meta)
	_ = db.Put([]byte(fileMetaPrefix+key), metaBytes)
	return thumbBytes, "image/jpeg", nw, nh, nil
}

func (db *DB) GetFileMetadata(key string) (*FileMetadata, error) {
	metaKey := []byte(fileMetaPrefix + key)
	metaBytes, err := db.Get(metaKey)
	if err != nil {
		return nil, translateFileError(err)
	}

	var meta FileMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func translateFileError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "key not found") {
		return ErrFileNotFound
	}
	return err
}

func generateFileKey() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

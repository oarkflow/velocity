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

	meta := &FileMetadata{
		Key:         key,
		Filename:    filename,
		ContentType: contentType,
		Size:        int64(len(data)),
		UploadedAt:  time.Now().UTC(),
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}

	dataKey := []byte(fileDataPrefix + key)
	metaKey := []byte(fileMetaPrefix + key)

	if err := db.Put(dataKey, data); err != nil {
		return nil, err
	}

	if err := db.Put(metaKey, metaBytes); err != nil {
		db.Delete(dataKey)
		return nil, err
	}

	// If image, synchronously generate thumbnail and update metadata
	if strings.HasPrefix(contentType, "image/") {
		if thumbBytes, _, w, h, err := db.GenerateThumbnail(key, 200); err == nil && len(thumbBytes) > 0 {
			meta.ThumbnailWidth = w
			meta.ThumbnailHeight = h
			meta.ThumbnailURL = "/api/files/" + key + "/thumbnail"
			metaBytes, _ = json.Marshal(meta)
			_ = db.Put(metaKey, metaBytes) // best-effort update
		}
	}

	return meta, nil
}

func (db *DB) GetFile(key string) ([]byte, *FileMetadata, error) {
	dataKey := []byte(fileDataPrefix + key)

	data, err := db.Get(dataKey)
	if err != nil {
		return nil, nil, translateFileError(err)
	}

	meta, err := db.GetFileMetadata(key)
	if err != nil {
		return nil, nil, err
	}

	return data, meta, nil
}

func (db *DB) DeleteFile(key string) error {
	if _, err := db.GetFileMetadata(key); err != nil {
		return err
	}

	metaKey := []byte(fileMetaPrefix + key)
	dataKey := []byte(fileDataPrefix + key)
	if err := db.Delete(dataKey); err != nil {
		return err
	}
	if err := db.Delete(metaKey); err != nil {
		return err
	}
	return nil
}

func (db *DB) ListFiles() ([]FileMetadata, error) {
	keys := db.Keys()
	files := make([]FileMetadata, 0)

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

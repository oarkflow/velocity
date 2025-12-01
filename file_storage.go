package velocity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	fileDataPrefix = "file:data:"
	fileMetaPrefix = "file:meta:"
)

var (
	ErrFileNotFound = errors.New("file not found")
	ErrFileExists   = errors.New("file already exists")
)

type FileMetadata struct {
	Key         string    `json:"key"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	UploadedAt  time.Time `json:"uploaded_at"`
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

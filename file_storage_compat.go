package velocity

import (
	"bytes"
	"io"
	"time"
)

// Compatibility layer for legacy file storage API
// These methods wrap the new object storage API for backward compatibility

const (
	FileDataPrefix  = "obj:data:"  // Reuse object storage prefix
	FileMetaPrefix  = "obj:meta:"  // Reuse object storage prefix
	FileThumbPrefix = "obj:thumb:" // Keep for thumbnails
)

var (
	ErrFileNotFound = ErrObjectNotFound
	ErrFileExists   = ErrObjectExists
)

// FileMetadata provides backward compatibility with old API
type FileMetadata struct {
	Key             string            `json:"key"`
	Filename        string            `json:"filename"`
	ContentType     string            `json:"content_type"`
	Size            int64             `json:"size"`
	UploadedAt      time.Time         `json:"uploaded_at"`
	ThumbnailWidth  int               `json:"thumbnail_width,omitempty"`
	ThumbnailHeight int               `json:"thumbnail_height,omitempty"`
	ThumbnailURL    string            `json:"thumbnail_url,omitempty"`
}

// Convert ObjectMetadata to FileMetadata
func objectToFileMetadata(obj *ObjectMetadata) *FileMetadata {
	return &FileMetadata{
		Key:         obj.Path, // Use path as key for lookups
		Filename:    obj.Name,
		ContentType: obj.ContentType,
		Size:        obj.Size,
		UploadedAt:  obj.CreatedAt,
	}
}

// StoreFile stores a file using the new object storage system
func (db *DB) StoreFile(key, filename, contentType string, data []byte) (*FileMetadata, error) {
	return db.StoreFileStream(key, filename, contentType, bytes.NewReader(data), int64(len(data)))
}

// StoreFileStream stores a file stream using the new object storage system
func (db *DB) StoreFileStream(key, filename, contentType string, r io.Reader, size int64) (*FileMetadata, error) {
	// Use filename as path, or key if provided
	path := filename
	if key != "" {
		path = key
	}

	// Default user for backward compatibility
	user := "system"

	opts := &ObjectOptions{
		Encrypt: true, // Enable encryption by default
		ACL: &ObjectACL{
			Owner:       user,
			Permissions: map[string][]string{user: {PermissionFull}},
			Public:      true, // Make public for backward compatibility
		},
	}

	obj, err := db.StoreObjectStream(path, contentType, user, r, size, opts)
	if err != nil {
		return nil, err
	}

	return objectToFileMetadata(obj), nil
}

// GetFile retrieves a file using the new object storage system
func (db *DB) GetFile(key string) ([]byte, *FileMetadata, error) {
	user := "system"

	data, obj, err := db.GetObject(key, user)
	if err != nil {
		return nil, nil, err
	}

	return data, objectToFileMetadata(obj), nil
}

// DeleteFile deletes a file using the new object storage system
func (db *DB) DeleteFile(key string) error {
	user := "system"
	return db.DeleteObject(key, user)
}

// ListFiles lists all files using the new object storage system
func (db *DB) ListFiles() ([]FileMetadata, error) {
	opts := ObjectListOptions{
		Folder:    "",
		Recursive: true,
		MaxKeys:   1000,
	}

	objects, err := db.ListObjects(opts)
	if err != nil {
		return nil, err
	}

	files := make([]FileMetadata, len(objects))
	for i, obj := range objects {
		files[i] = *objectToFileMetadata(&obj)
	}

	return files, nil
}

// HasFile checks if a file exists
func (db *DB) HasFile(key string) bool {
	_, err := db.GetObjectMetadata(key)
	return err == nil
}

// GetThumbnail returns a cached thumbnail (placeholder - needs implementation)
func (db *DB) GetThumbnail(key string) ([]byte, string, int, int, error) {
	// For now, delegate to GetFile
	data, meta, err := db.GetFile(key)
	if err != nil {
		return nil, "", 0, 0, err
	}
	return data, meta.ContentType, 0, 0, nil
}

// GenerateThumbnail generates a thumbnail (placeholder - needs implementation)
func (db *DB) GenerateThumbnail(key string, maxDim int) ([]byte, string, int, int, error) {
	// For now, just return the original file
	data, meta, err := db.GetFile(key)
	if err != nil {
		return nil, "", 0, 0, err
	}
	return data, meta.ContentType, 0, 0, nil
}

// GetFileMetadata retrieves file metadata
func (db *DB) GetFileMetadata(key string) (*FileMetadata, error) {
	obj, err := db.GetObjectMetadata(key)
	if err != nil {
		return nil, err
	}
	return objectToFileMetadata(obj), nil
}

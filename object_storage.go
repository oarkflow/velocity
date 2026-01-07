package velocity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// Object storage prefixes
	ObjectDataPrefix      = "obj:data:"
	ObjectMetaPrefix      = "obj:meta:"
	ObjectVersionPrefix   = "obj:version:"
	ObjectACLPrefix       = "obj:acl:"
	ObjectFolderPrefix    = "obj:folder:"
	ObjectIndexPrefix     = "obj:index:"

	// Folder separator
	FolderSeparator = "/"

	// Default version
	DefaultVersion = "v1"
)

var (
	ErrObjectNotFound      = errors.New("object not found")
	ErrObjectExists        = errors.New("object already exists")
	ErrInvalidPath         = errors.New("invalid object path")
	ErrAccessDenied        = errors.New("access denied")
	ErrInvalidVersion      = errors.New("invalid version")
	ErrFolderNotEmpty      = errors.New("folder not empty")
)

// ObjectMetadata represents metadata for a stored object
type ObjectMetadata struct {
	ObjectID        string            `json:"object_id"`
	Path            string            `json:"path"`
	Folder          string            `json:"folder"`
	Name            string            `json:"name"`
	ContentType     string            `json:"content_type"`
	Size            int64             `json:"size"`
	Hash            string            `json:"hash"`            // SHA256 hash
	Encrypted       bool              `json:"encrypted"`
	EncryptionAlgo  string            `json:"encryption_algo,omitempty"`
	Version         string            `json:"version"`
	VersionID       string            `json:"version_id"`
	IsLatest        bool              `json:"is_latest"`
	CreatedAt       time.Time         `json:"created_at"`
	ModifiedAt      time.Time         `json:"modified_at"`
	CreatedBy       string            `json:"created_by"`
	ModifiedBy      string            `json:"modified_by"`
	Tags            map[string]string `json:"tags,omitempty"`
	CustomMetadata  map[string]string `json:"custom_metadata,omitempty"`
	Checksum        string            `json:"checksum"`
	StorageClass    string            `json:"storage_class"`
}

// ObjectACL represents access control for an object
type ObjectACL struct {
	ObjectID    string              `json:"object_id"`
	Owner       string              `json:"owner"`
	Permissions map[string][]string `json:"permissions"` // user/role -> []permission
	Public      bool                `json:"public"`
	CreatedAt   time.Time           `json:"created_at"`
	ModifiedAt  time.Time           `json:"modified_at"`
}

// Permission constants
const (
	PermissionRead   = "read"
	PermissionWrite  = "write"
	PermissionDelete = "delete"
	PermissionACL    = "acl"
	PermissionFull   = "full"
)

// ObjectVersion represents a version of an object
type ObjectVersion struct {
	VersionID   string    `json:"version_id"`
	ObjectID    string    `json:"object_id"`
	Size        int64     `json:"size"`
	Hash        string    `json:"hash"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	IsLatest    bool      `json:"is_latest"`
	DeleteMarker bool     `json:"delete_marker"`
}

// FolderMetadata represents a folder/directory
type FolderMetadata struct {
	Path       string            `json:"path"`
	Name       string            `json:"name"`
	Parent     string            `json:"parent"`
	CreatedAt  time.Time         `json:"created_at"`
	CreatedBy  string            `json:"created_by"`
	ModifiedAt time.Time         `json:"modified_at"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// ObjectListOptions for filtering and pagination
type ObjectListOptions struct {
	Prefix      string
	Folder      string
	MaxKeys     int
	StartAfter  string
	Recursive   bool
	IncludeACL  bool
	User        string // for permission filtering
}

// StoreObject stores an object with zero-trust security
func (db *DB) StoreObject(path, contentType, user string, data []byte, opts *ObjectOptions) (*ObjectMetadata, error) {
	return db.StoreObjectStream(path, contentType, user, bytes.NewReader(data), int64(len(data)), opts)
}

// ObjectOptions for storing objects
type ObjectOptions struct {
	Version        string
	Tags           map[string]string
	CustomMetadata map[string]string
	Encrypt        bool
	ACL            *ObjectACL
	StorageClass   string
}

// StoreObjectStream stores an object from a stream with encryption and versioning
func (db *DB) StoreObjectStream(path, contentType, user string, r io.Reader, size int64, opts *ObjectOptions) (*ObjectMetadata, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}

	// Validate and normalize path
	path = normalizePath(path)
	if !isValidPath(path) {
		return nil, ErrInvalidPath
	}

	if opts == nil {
		opts = &ObjectOptions{
			Version: DefaultVersion,
			Encrypt: true,
		}
	}

	if opts.Version == "" {
		opts.Version = DefaultVersion
	}

	// Ensure object storage directory exists
	if db.filesDir == "" {
		db.filesDir = filepath.Join(db.path, "files")
		os.MkdirAll(db.filesDir, 0755)
	}

	objectsDir := filepath.Join(db.filesDir, "objects")
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		return nil, err
	}

	// Generate object ID
	objectID := generateObjectID()
	versionID := generateVersionID()

	// Create folder structure if needed
	folder := extractFolder(path)
	if folder != "" {
		if err := db.CreateFolder(folder, user); err != nil && !errors.Is(err, ErrObjectExists) {
			return nil, err
		}
	}

	// Create temp file
	tmp, err := os.CreateTemp(objectsDir, "upload-*.tmp")
	if err != nil {
		return nil, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()

	// Compute hash while copying
	hash := sha256.New()
	tee := io.TeeReader(r, hash)

	var written int64
	var finalData []byte

	if opts.Encrypt && db.crypto != nil {
		// Read all data for encryption (for streaming encryption, we'd need a different approach)
		buf := new(bytes.Buffer)
		written, err = io.Copy(buf, io.LimitReader(tee, db.MaxUploadSize+1))
		if err != nil {
			return nil, err
		}
		if written > db.MaxUploadSize {
			return nil, fmt.Errorf("uploaded object too large")
		}

		// Encrypt data
		plaintext := buf.Bytes()
		nonce, ciphertext, err := db.crypto.Encrypt(plaintext, []byte(objectID))
		if err != nil {
			return nil, err
		}

		// Combine nonce and ciphertext
		finalData = append(nonce, ciphertext...)
		if _, err := tmp.Write(finalData); err != nil {
			return nil, err
		}
	} else {
		written, err = io.Copy(tmp, io.LimitReader(tee, db.MaxUploadSize+1))
		if err != nil {
			return nil, err
		}
		if written > db.MaxUploadSize {
			return nil, fmt.Errorf("uploaded object too large")
		}
	}

	hashStr := hex.EncodeToString(hash.Sum(nil))

	// Create metadata
	meta := &ObjectMetadata{
		ObjectID:       objectID,
		Path:           path,
		Folder:         folder,
		Name:           extractName(path),
		ContentType:    contentType,
		Size:           size,
		Hash:           hashStr,
		Encrypted:      opts.Encrypt && db.crypto != nil,
		EncryptionAlgo: "ChaCha20-Poly1305",
		Version:        opts.Version,
		VersionID:      versionID,
		IsLatest:       true,
		CreatedAt:      time.Now().UTC(),
		ModifiedAt:     time.Now().UTC(),
		CreatedBy:      user,
		ModifiedBy:     user,
		Tags:           opts.Tags,
		CustomMetadata: opts.CustomMetadata,
		Checksum:       hashStr,
		StorageClass:   opts.StorageClass,
	}

	if meta.StorageClass == "" {
		meta.StorageClass = "STANDARD"
	}

	// Move temp file to final location
	finalPath := filepath.Join(objectsDir, objectID, versionID)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0700); err != nil {
		return nil, err
	}

	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), finalPath); err != nil {
		return nil, err
	}

	// Check if object already exists and mark old versions as not latest
	existingMeta, err := db.GetObjectMetadata(path)
	if err == nil {
		existingMeta.IsLatest = false
		if err := db.saveObjectMetadata(existingMeta); err != nil {
			// Log error but continue
		}
	}

	// Store metadata
	if err := db.saveObjectMetadata(meta); err != nil {
		_ = os.Remove(finalPath)
		return nil, err
	}

	// Store version info
	version := &ObjectVersion{
		VersionID:    versionID,
		ObjectID:     objectID,
		Size:         size,
		Hash:         hashStr,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    user,
		IsLatest:     true,
		DeleteMarker: false,
	}
	if err := db.saveObjectVersion(path, version); err != nil {
		// Log error but continue
	}

	// Create or update ACL
	if opts.ACL != nil {
		if err := db.SetObjectACL(path, opts.ACL); err != nil {
			// Log error but continue
		}
	} else {
		// Create default ACL
		defaultACL := &ObjectACL{
			ObjectID:    objectID,
			Owner:       user,
			Permissions: map[string][]string{user: {PermissionFull}},
			Public:      false,
			CreatedAt:   time.Now().UTC(),
			ModifiedAt:  time.Now().UTC(),
		}
		if err := db.SetObjectACL(path, defaultACL); err != nil {
			// Log error but continue
		}
	}

	// Create index entry for path lookup
	if err := db.indexObject(path, objectID); err != nil {
		// Log error but continue
	}

	return meta, nil
}

// GetObject retrieves an object by path
func (db *DB) GetObject(path, user string) ([]byte, *ObjectMetadata, error) {
	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return nil, nil, err
	}

	// Check permissions
	if !db.hasPermission(path, user, PermissionRead) {
		return nil, nil, ErrAccessDenied
	}

	// Read from filesystem
	objectsDir := filepath.Join(db.filesDir, "objects")
	filePath := filepath.Join(objectsDir, meta.ObjectID, meta.VersionID)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt if necessary
	if meta.Encrypted && db.crypto != nil {
		// Extract nonce and ciphertext
		if len(data) < 24 {
			return nil, nil, fmt.Errorf("invalid encrypted data")
		}
		nonce := data[:24]
		ciphertext := data[24:]

		plaintext, err := db.crypto.Decrypt(nonce, ciphertext, []byte(meta.ObjectID))
		if err != nil {
			return nil, nil, err
		}
		data = plaintext
	}

	return data, meta, nil
}

// GetObjectStream retrieves an object as a stream
func (db *DB) GetObjectStream(path, user string) (io.ReadCloser, *ObjectMetadata, error) {
	// For now, read all data and return as reader
	// TODO: Implement true streaming with chunked encryption
	data, meta, err := db.GetObject(path, user)
	if err != nil {
		return nil, nil, err
	}

	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

// DeleteObject deletes an object (soft delete with version marker)
func (db *DB) DeleteObject(path, user string) error {
	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return err
	}

	// Check permissions
	if !db.hasPermission(path, user, PermissionDelete) {
		return ErrAccessDenied
	}

	// Create delete marker version
	versionID := generateVersionID()
	version := &ObjectVersion{
		VersionID:    versionID,
		ObjectID:     meta.ObjectID,
		Size:         0,
		Hash:         "",
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    user,
		IsLatest:     true,
		DeleteMarker: true,
	}

	// Mark current version as not latest
	meta.IsLatest = false
	if err := db.saveObjectMetadata(meta); err != nil {
		return err
	}

	// Save delete marker
	if err := db.saveObjectVersion(path, version); err != nil {
		return err
	}

	// Remove index
	indexKey := []byte(ObjectIndexPrefix + path)
	_ = db.Delete(indexKey)

	return nil
}

// HardDeleteObject permanently deletes an object and all versions
func (db *DB) HardDeleteObject(path, user string) error {
	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return err
	}

	// Check permissions
	if !db.hasPermission(path, user, PermissionDelete) {
		return ErrAccessDenied
	}

	// Delete all versions from filesystem
	objectsDir := filepath.Join(db.filesDir, "objects")
	objectDir := filepath.Join(objectsDir, meta.ObjectID)
	if err := os.RemoveAll(objectDir); err != nil {
		return err
	}

	// Delete metadata
	metaKey := []byte(ObjectMetaPrefix + path)
	_ = db.Delete(metaKey)

	// Delete ACL
	aclKey := []byte(ObjectACLPrefix + path)
	_ = db.Delete(aclKey)

	// Delete versions
	versionKey := []byte(ObjectVersionPrefix + path)
	_ = db.Delete(versionKey)

	// Delete index
	indexKey := []byte(ObjectIndexPrefix + path)
	_ = db.Delete(indexKey)

	return nil
}

// ListObjects lists objects in a folder
func (db *DB) ListObjects(opts ObjectListOptions) ([]ObjectMetadata, error) {
	objects := make([]ObjectMetadata, 0)

	// Scan all metadata keys
	offset := 0
	limit := 100
	count := 0
	maxKeys := opts.MaxKeys
	if maxKeys == 0 {
		maxKeys = 1000
	}

	for {
		keys, _ := db.KeysPage(offset, limit)
		if len(keys) == 0 {
			break
		}

		for _, key := range keys {
			keyStr := string(key)
			if !strings.HasPrefix(keyStr, ObjectMetaPrefix) {
				continue
			}

			path := strings.TrimPrefix(keyStr, ObjectMetaPrefix)

			// Apply filters
			if opts.Prefix != "" && !strings.HasPrefix(path, opts.Prefix) {
				continue
			}

			if opts.Folder != "" {
				if opts.Recursive {
					if !strings.HasPrefix(path, opts.Folder+FolderSeparator) {
						continue
					}
				} else {
					folder := extractFolder(path)
					if folder != opts.Folder {
						continue
					}
				}
			}

			if opts.StartAfter != "" && path <= opts.StartAfter {
				continue
			}

			// Get metadata
			raw, err := db.Get(key)
			if err != nil {
				continue
			}

			var meta ObjectMetadata
			if err := json.Unmarshal(raw, &meta); err != nil {
				continue
			}

			// Only show latest versions
			if !meta.IsLatest {
				continue
			}

			// Check permissions if user specified
			if opts.User != "" && !db.hasPermission(path, opts.User, PermissionRead) {
				continue
			}

			objects = append(objects, meta)
			count++

			if count >= maxKeys {
				break
			}
		}

		if count >= maxKeys || len(keys) < limit {
			break
		}
		offset += limit
	}

	// Sort by path
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Path < objects[j].Path
	})

	return objects, nil
}

// CreateFolder creates a folder in the object storage
func (db *DB) CreateFolder(path, user string) error {
	path = normalizePath(path)
	if !isValidPath(path) {
		return ErrInvalidPath
	}

	// Check if folder already exists
	folderKey := []byte(ObjectFolderPrefix + path)
	if db.Has(folderKey) {
		return ErrObjectExists
	}

	// Create parent folders if needed
	parent := extractFolder(path)
	if parent != "" {
		if err := db.CreateFolder(parent, user); err != nil && !errors.Is(err, ErrObjectExists) {
			return err
		}
	}

	// Create folder metadata
	folder := &FolderMetadata{
		Path:       path,
		Name:       extractName(path),
		Parent:     parent,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  user,
		ModifiedAt: time.Now().UTC(),
	}

	folderBytes, err := json.Marshal(folder)
	if err != nil {
		return err
	}

	return db.Put(folderKey, folderBytes)
}

// DeleteFolder deletes a folder (must be empty)
func (db *DB) DeleteFolder(path, user string) error {
	path = normalizePath(path)

	// Check if folder exists
	folderKey := []byte(ObjectFolderPrefix + path)
	if !db.Has(folderKey) {
		return ErrObjectNotFound
	}

	// Check if folder is empty
	opts := ObjectListOptions{
		Folder:    path,
		MaxKeys:   1,
		Recursive: false,
	}
	objects, err := db.ListObjects(opts)
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		return ErrFolderNotEmpty
	}

	return db.Delete(folderKey)
}

// GetObjectMetadata retrieves metadata for an object
func (db *DB) GetObjectMetadata(path string) (*ObjectMetadata, error) {
	metaKey := []byte(ObjectMetaPrefix + path)
	metaBytes, err := db.Get(metaKey)
	if err != nil {
		return nil, translateObjectError(err)
	}

	var meta ObjectMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// SetObjectACL sets access control for an object
func (db *DB) SetObjectACL(path string, acl *ObjectACL) error {
	aclKey := []byte(ObjectACLPrefix + path)
	aclBytes, err := json.Marshal(acl)
	if err != nil {
		return err
	}

	return db.Put(aclKey, aclBytes)
}

// GetObjectACL retrieves access control for an object
func (db *DB) GetObjectACL(path string) (*ObjectACL, error) {
	aclKey := []byte(ObjectACLPrefix + path)
	aclBytes, err := db.Get(aclKey)
	if err != nil {
		return nil, translateObjectError(err)
	}

	var acl ObjectACL
	if err := json.Unmarshal(aclBytes, &acl); err != nil {
		return nil, err
	}

	return &acl, nil
}

// Helper functions

func (db *DB) saveObjectMetadata(meta *ObjectMetadata) error {
	metaKey := []byte(ObjectMetaPrefix + meta.Path)
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return db.Put(metaKey, metaBytes)
}

func (db *DB) saveObjectVersion(path string, version *ObjectVersion) error {
	versionKey := []byte(ObjectVersionPrefix + path + ":" + version.VersionID)
	versionBytes, err := json.Marshal(version)
	if err != nil {
		return err
	}
	return db.Put(versionKey, versionBytes)
}

func (db *DB) indexObject(path, objectID string) error {
	indexKey := []byte(ObjectIndexPrefix + path)
	return db.Put(indexKey, []byte(objectID))
}

func (db *DB) hasPermission(path, user, permission string) bool {
	if user == "" {
		return false
	}

	acl, err := db.GetObjectACL(path)
	if err != nil {
		return false
	}

	// Check if public and read permission
	if acl.Public && permission == PermissionRead {
		return true
	}

	// Check if owner
	if acl.Owner == user {
		return true
	}

	// Check explicit permissions
	perms, ok := acl.Permissions[user]
	if !ok {
		return false
	}

	for _, p := range perms {
		if p == PermissionFull || p == permission {
			return true
		}
	}

	return false
}

func normalizePath(path string) string {
	// Remove leading/trailing slashes
	path = strings.Trim(path, FolderSeparator)
	// Replace multiple slashes with single
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

func isValidPath(path string) bool {
	if path == "" {
		return false
	}
	// Check for invalid characters
	if strings.Contains(path, "..") {
		return false
	}
	return true
}

func extractFolder(path string) string {
	idx := strings.LastIndex(path, FolderSeparator)
	if idx == -1 {
		return ""
	}
	return path[:idx]
}

func extractName(path string) string {
	idx := strings.LastIndex(path, FolderSeparator)
	if idx == -1 {
		return path
	}
	return path[idx+1:]
}

func generateObjectID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("obj-%d", time.Now().UnixNano())
	}
	return "obj-" + hex.EncodeToString(buf)
}

func generateVersionID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("ver-%d", time.Now().UnixNano())
	}
	return "ver-" + hex.EncodeToString(buf)
}

func translateObjectError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "key not found") {
		return ErrObjectNotFound
	}
	return err
}

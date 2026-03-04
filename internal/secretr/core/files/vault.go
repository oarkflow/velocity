// Package files provides encrypted file storage functionality.
package files

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/oarkflow/velocity"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

const (
	DefaultChunkSize = 64 * 1024   // 64KB chunks
	MaxChunkSize     = 1024 * 1024 // 1MB max
	SystemUserID     = "__system__"  // System user for internal operations
)

var (
	ErrFileNotFound = errors.New("files: not found")
	ErrFileExists   = errors.New("files: already exists")
	ErrFileSealed   = errors.New("files: file is sealed")
	ErrFileExpired  = errors.New("files: file has expired")
)

// Vault manages encrypted file storage
type Vault struct {
	store      *storage.Store
	crypto     *crypto.Engine
	fileStore  *storage.TypedStore[types.EncryptedFile]
	chunkStore *storage.TypedStore[types.FileChunk]
	keyManager KeyProvider
	protection *ProtectionManager
	chunkSize  int
}

// KeyProvider provides encryption keys
type KeyProvider interface {
	GetKey(ctx context.Context, id types.ID) ([]byte, error)
	GetCurrentKeyID(ctx context.Context) (types.ID, error)
}

// VaultConfig configures the file vault
type VaultConfig struct {
	Store      *storage.Store
	KeyManager KeyProvider
	Protection *ProtectionManager
	ChunkSize  int
}

// NewVault creates a new file vault
func NewVault(cfg VaultConfig) *Vault {
	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	return &Vault{
		store:      cfg.Store,
		crypto:     crypto.NewEngine(""),
		fileStore:  storage.NewTypedStore[types.EncryptedFile](cfg.Store, storage.CollectionFiles),
		chunkStore: storage.NewTypedStore[types.FileChunk](cfg.Store, storage.CollectionFileChunks),
		keyManager: cfg.KeyManager,
		protection: cfg.Protection,
		chunkSize:  chunkSize,
	}
}

// Upload uploads and encrypts a file
func (v *Vault) Upload(ctx context.Context, opts UploadOptions) (*types.EncryptedFile, error) {
	// Check if file exists
	if existing, _ := v.GetMetadata(ctx, opts.Name); existing != nil {
		if !opts.Overwrite {
			return nil, ErrFileExists
		}
		// Delete existing
		v.Delete(ctx, opts.Name, opts.UploaderID)
	}

	id, err := v.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Get encryption key
	keyID, err := v.keyManager.GetCurrentKeyID(ctx)
	if err != nil {
		return nil, err
	}
	key, err := v.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(key)

	// Read and encrypt in chunks
	hasher := sha256.New()
	var totalSize int64
	chunkIndex := 0

	for {
		chunk := make([]byte, v.chunkSize)
		n, err := opts.Reader.Read(chunk)
		if n > 0 {
			chunk = chunk[:n]
			hasher.Write(chunk)
			totalSize += int64(n)

			// Encrypt chunk
			encryptedChunk, err := v.crypto.Encrypt(key, chunk, []byte(fmt.Sprintf("%s:%d", id, chunkIndex)))
			if err != nil {
				return nil, fmt.Errorf("files: failed to encrypt chunk: %w", err)
			}

			fileChunk := &types.FileChunk{
				FileID:        id,
				Index:         chunkIndex,
				EncryptedData: encryptedChunk,
				Hash:          v.crypto.Hash(chunk),
				Size:          n,
			}

			// Store chunk as object (not as key-value)
			chunkData, err := json.Marshal(fileChunk)
			if err != nil {
				return nil, fmt.Errorf("files: failed to marshal chunk: %w", err)
			}

			chunkPath := fmt.Sprintf("%s/%s:%d", storage.CollectionFileChunks, id, chunkIndex)
			chunkOpts := &velocity.ObjectOptions{
				Encrypt: false, // Already encrypted in EncryptedData field
				Version: "v1",
				ACL: &velocity.ObjectACL{
					Owner:  string(opts.UploaderID),
					Public: true, // Make publicly readable
					Permissions: map[string][]string{
						string(opts.UploaderID): {velocity.PermissionFull},
					},
				},
			}

			if _, err := v.store.DB().StoreObject(chunkPath, "application/octet-stream", string(opts.UploaderID), chunkData, chunkOpts); err != nil {
				return nil, fmt.Errorf("files: failed to store chunk: %w", err)
			}

			chunkIndex++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("files: read error: %w", err)
		}
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	file := &types.EncryptedFile{
		ID:           id,
		Name:         opts.Name,
		OriginalName: opts.OriginalName,
		Size:         totalSize,
		ChunkCount:   chunkIndex,
		ContentType:  opts.ContentType,
		Hash:         hasher.Sum(nil),
		CreatedAt:    now,
		UpdatedAt:    now,
		ExpiresAt:    expiresAt,
		Sealed:       false,
		Status:       types.StatusActive,
		Metadata:     opts.Metadata,
		KeyID:        keyID,
		Provenance: &types.Provenance{
			CreatedBy:   opts.UploaderID,
			CreatedAt:   now,
			CreatedFrom: opts.DeviceFingerprint,
		},
	}

	// Store file metadata as object (not as key-value)
	fileData, err := json.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("files: failed to marshal file metadata: %w", err)
	}

	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, opts.Name)
	objectOpts := &velocity.ObjectOptions{
		Encrypt: true,
		Version: "v1",
		Tags: map[string]string{
			"owner": string(opts.UploaderID),
			"type":  "file_metadata",
		},
		ACL: &velocity.ObjectACL{
			Owner:  string(opts.UploaderID),
			Public: true, // Make publicly readable for listing
			Permissions: map[string][]string{
				string(opts.UploaderID): {velocity.PermissionFull},
			},
		},
	}

	if _, err := v.store.DB().StoreObject(objectPath, "application/json", string(opts.UploaderID), fileData, objectOpts); err != nil {
		return nil, fmt.Errorf("files: failed to store file metadata: %w", err)
	}

	return file, nil
}

// UploadOptions holds file upload options
type UploadOptions struct {
	Name              string
	OriginalName      string
	ContentType       string
	Reader            io.Reader
	ExpiresIn         time.Duration
	Overwrite         bool
	Metadata          types.Metadata
	UploaderID        types.ID
	DeviceFingerprint string
}

// SetProtectionPolicy sets the protection policy for a file
func (v *Vault) SetProtectionPolicy(ctx context.Context, policy *FileProtectionPolicy) error {
	if v.protection == nil {
		return errors.New("protection manager not enabled")
	}
	// Check if update or create. For now, simple create/overwrite in manager.
	// Manager.CreatePolicy generates new ID. If we want to support updates, we need logic.
	// For CLI simplicty, let's try Update if exists, else Create.
	existing, err := v.protection.GetPolicy(ctx, policy.FileID)
	if err == nil && existing != nil {
		return v.protection.UpdatePolicy(ctx, existing.ID, policy)
	}
	return v.protection.CreatePolicy(ctx, policy)
}

// GetProtectionPolicy retrieves the protection policy for a file
func (v *Vault) GetProtectionPolicy(ctx context.Context, fileID types.ID) (*FileProtectionPolicy, error) {
	if v.protection == nil {
		return nil, errors.New("protection manager not enabled")
	}
	return v.protection.GetPolicy(ctx, fileID)
}

// KillFile remotely kills a file
func (v *Vault) KillFile(ctx context.Context, name string, killedBy types.ID, reason string) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}
	if v.protection == nil {
		return errors.New("protection manager not enabled")
	}
	return v.protection.KillFile(ctx, file.ID, killedBy, reason)
}

// ReviveFile revives a killed file
func (v *Vault) ReviveFile(ctx context.Context, name string) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}
	if v.protection == nil {
		return errors.New("protection manager not enabled")
	}
	return v.protection.ReviveFile(ctx, file.ID)
}

// DownloadOptions holds options for file download
type DownloadOptions struct {
	AccessorID  types.ID
	DeviceID    types.ID
	IPAddress   string
	MFAVerified bool
}

// Download downloads and decrypts a file
func (v *Vault) Download(ctx context.Context, name string, opts DownloadOptions, writer io.Writer) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}

	if file.Sealed {
		return ErrFileSealed
	}

	// Check protection policy
	if v.protection != nil {
		res, err := v.protection.ValidateAccess(ctx, ValidateAccessOptions{
			FileID:      file.ID,
			AccessorID:  opts.AccessorID,
			DeviceID:    opts.DeviceID,
			Action:      "download",
			IPAddress:   opts.IPAddress,
			MFAVerified: opts.MFAVerified,
		})
		if err != nil {
			return err
		}
		if !res.Allowed {
			return errors.New(res.Reason)
		}
	}

	if file.ExpiresAt != nil && types.Now() > *file.ExpiresAt {
		return ErrFileExpired
	}

	key, err := v.keyManager.GetKey(ctx, file.KeyID)
	if err != nil {
		return err
	}
	defer security.Zeroize(key)

	for i := 0; i < file.ChunkCount; i++ {
		chunkPath := fmt.Sprintf("%s/%s:%d", storage.CollectionFileChunks, file.ID, i)
		chunkData, _, err := v.store.DB().GetObject(chunkPath, string(opts.AccessorID))
		if err != nil {
			return fmt.Errorf("files: failed to read chunk %d: %w", i, err)
		}

		var chunk types.FileChunk
		if err := json.Unmarshal(chunkData, &chunk); err != nil {
			return fmt.Errorf("files: failed to unmarshal chunk %d: %w", i, err)
		}

		plaintext, err := v.crypto.Decrypt(key, chunk.EncryptedData, []byte(fmt.Sprintf("%s:%d", file.ID, i)))
		if err != nil {
			return fmt.Errorf("files: failed to decrypt chunk %d: %w", i, err)
		}

		if _, err := writer.Write(plaintext); err != nil {
			security.Zeroize(plaintext)
			return fmt.Errorf("files: write error: %w", err)
		}
		security.Zeroize(plaintext)
	}

	return nil
}

// GetMetadata retrieves file metadata
func (v *Vault) GetMetadata(ctx context.Context, name string) (*types.EncryptedFile, error) {
	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, name)
	// Use system user for retrieval since objects are public
	fileData, _, err := v.store.DB().GetObject(objectPath, SystemUserID)
	if err != nil {
		if errors.Is(err, velocity.ErrObjectNotFound) || errors.Is(err, velocity.ErrAccessDenied) {
			return nil, ErrFileNotFound
		}
		return nil, fmt.Errorf("files: failed to get file metadata: %w", err)
	}

	var file types.EncryptedFile
	if err := json.Unmarshal(fileData, &file); err != nil {
		return nil, fmt.Errorf("files: failed to unmarshal file metadata: %w", err)
	}

	if file.Status == types.StatusRevoked {
		return nil, ErrFileNotFound
	}

	return &file, nil
}

// List lists files
func (v *Vault) List(ctx context.Context, opts ListOptions) ([]*types.EncryptedFile, error) {
	// Use velocity ListObjects to list file objects
	// Try using Prefix instead of Folder for better compatibility
	prefix := storage.CollectionFiles
	if opts.Prefix != "" {
		prefix = fmt.Sprintf("%s/%s", storage.CollectionFiles, opts.Prefix)
	}

	listOpts := velocity.ObjectListOptions{
		Prefix:    prefix,
		Recursive: true,
		MaxKeys:   1000,
	}

	objects, err := v.store.DB().ListObjects(listOpts)
	if err != nil {
		return nil, fmt.Errorf("files: failed to list objects: %w", err)
	}

	result := make([]*types.EncryptedFile, 0, len(objects))
	for _, obj := range objects {
		// Get owner from tags if available, otherwise use system user
		ownerID := SystemUserID
		if obj.Tags != nil {
			if owner, ok := obj.Tags["owner"]; ok {
				ownerID = owner
			}
		}
		fileData, _, err := v.store.DB().GetObject(obj.Path, ownerID)
		if err != nil {
			continue // Skip files that can't be read
		}

		var file types.EncryptedFile
		if err := json.Unmarshal(fileData, &file); err != nil {
			continue // Skip files that can't be unmarshaled
		}

		if file.Status == types.StatusRevoked && !opts.IncludeDeleted {
			continue
		}
		result = append(result, &file)
	}

	return result, nil
}

// ListOptions holds list options
type ListOptions struct {
	Prefix         string
	IncludeDeleted bool
}

// Delete deletes a file
func (v *Vault) Delete(ctx context.Context, name string, deleterID types.ID) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}

	// Delete chunks using DeleteObject
	for i := 0; i < file.ChunkCount; i++ {
		chunkPath := fmt.Sprintf("%s/%s:%d", storage.CollectionFileChunks, file.ID, i)
		if err := v.store.DB().DeleteObject(chunkPath, string(deleterID)); err != nil {
			// Continue deleting other chunks even if one fails
			continue
		}
	}

	file.Status = types.StatusRevoked
	file.UpdatedAt = types.Now()

	if file.Provenance != nil {
		file.Provenance.Chain = append(file.Provenance.Chain, types.ProvenanceEntry{
			Action:    "delete",
			ActorID:   deleterID,
			Timestamp: types.Now(),
		})
	}

	// Update file metadata as deleted
	fileData, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("files: failed to marshal file metadata: %w", err)
	}

	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, name)
	objectOpts := &velocity.ObjectOptions{
		Encrypt: true,
		Version: "v1",
		ACL: &velocity.ObjectACL{
			Owner:  string(deleterID),
			Public: true, // Keep publicly readable
			Permissions: map[string][]string{
				string(deleterID): {velocity.PermissionFull},
			},
		},
	}

	if _, err := v.store.DB().StoreObject(objectPath, "application/json", string(deleterID), fileData, objectOpts); err != nil {
		return fmt.Errorf("files: failed to update file metadata: %w", err)
	}

	return nil
}

// Seal seals a file for long-term storage
func (v *Vault) Seal(ctx context.Context, name string, sealerID types.ID) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}

	file.Sealed = true
	file.UpdatedAt = types.Now()

	if file.Provenance != nil {
		file.Provenance.Chain = append(file.Provenance.Chain, types.ProvenanceEntry{
			Action:    "seal",
			ActorID:   sealerID,
			Timestamp: types.Now(),
		})
	}

	// Update file metadata
	fileData, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("files: failed to marshal file metadata: %w", err)
	}

	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, name)
	objectOpts := &velocity.ObjectOptions{
		Encrypt: true,
		Version: "v1",
		ACL: &velocity.ObjectACL{
			Owner:  string(sealerID),
			Public: true, // Keep publicly readable
			Permissions: map[string][]string{
				string(sealerID): {velocity.PermissionFull},
			},
		},
	}

	if _, err := v.store.DB().StoreObject(objectPath, "application/json", string(sealerID), fileData, objectOpts); err != nil {
		return fmt.Errorf("files: failed to update file metadata: %w", err)
	}

	return nil
}

// Unseal unseals a file
func (v *Vault) Unseal(ctx context.Context, name string, unsealerID types.ID) error {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}

	file.Sealed = false
	file.UpdatedAt = types.Now()

	if file.Provenance != nil {
		file.Provenance.Chain = append(file.Provenance.Chain, types.ProvenanceEntry{
			Action:    "unseal",
			ActorID:   unsealerID,
			Timestamp: types.Now(),
		})
	}

	// Update file metadata
	fileData, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("files: failed to marshal file metadata: %w", err)
	}

	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, name)
	objectOpts := &velocity.ObjectOptions{
		Encrypt: true,
		Version: "v1",
		ACL: &velocity.ObjectACL{
			Owner:  string(unsealerID),
			Public: true, // Keep publicly readable
			Permissions: map[string][]string{
				string(unsealerID): {velocity.PermissionFull},
			},
		},
	}

	if _, err := v.store.DB().StoreObject(objectPath, "application/json", string(unsealerID), fileData, objectOpts); err != nil {
		return fmt.Errorf("files: failed to update file metadata: %w", err)
	}

	return nil
}

// Shred cryptographically destroys a file
func (v *Vault) Shred(ctx context.Context, name string, shredderID types.ID, signerPrivKey []byte) (*crypto.KeyDestructionProof, error) {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	key, err := v.keyManager.GetKey(ctx, file.KeyID)
	if err != nil {
		return nil, err
	}

	proof, err := v.crypto.CreateDestructionProof(file.ID, key, shredderID, signerPrivKey)
	security.Zeroize(key)
	if err != nil {
		return nil, err
	}

	// Delete all chunks using DeleteObject
	for i := 0; i < file.ChunkCount; i++ {
		chunkPath := fmt.Sprintf("%s/%s:%d", storage.CollectionFileChunks, file.ID, i)
		v.store.DB().DeleteObject(chunkPath, string(shredderID))
	}

	// Delete file record using DeleteObject
	objectPath := fmt.Sprintf("%s/%s", storage.CollectionFiles, name)
	v.store.DB().DeleteObject(objectPath, string(shredderID))

	return proof, nil
}

// Export exports a file for offline sharing
func (v *Vault) Export(ctx context.Context, name string, exportKey []byte) ([]byte, error) {
	file, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	key, err := v.keyManager.GetKey(ctx, file.KeyID)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(key)

	// Collect all chunks using system user or file owner
	ownerID := SystemUserID
	if file.Provenance != nil {
		ownerID = string(file.Provenance.CreatedBy)
	}
	chunks := make([][]byte, file.ChunkCount)
	for i := 0; i < file.ChunkCount; i++ {
		chunkPath := fmt.Sprintf("%s/%s:%d", storage.CollectionFileChunks, file.ID, i)
		chunkData, _, err := v.store.DB().GetObject(chunkPath, ownerID)
		if err != nil {
			return nil, fmt.Errorf("files: failed to get chunk %d: %w", i, err)
		}

		var chunk types.FileChunk
		if err := json.Unmarshal(chunkData, &chunk); err != nil {
			return nil, fmt.Errorf("files: failed to unmarshal chunk %d: %w", i, err)
		}

		plaintext, err := v.crypto.Decrypt(key, chunk.EncryptedData, []byte(fmt.Sprintf("%s:%d", file.ID, i)))
		if err != nil {
			return nil, err
		}
		chunks[i] = plaintext
	}

	export := fileExport{
		Name:         file.Name,
		OriginalName: file.OriginalName,
		ContentType:  file.ContentType,
		Size:         file.Size,
		Hash:         file.Hash,
		Chunks:       chunks,
		Metadata:     file.Metadata,
	}

	exportData, err := json.Marshal(export)
	if err != nil {
		return nil, err
	}

	// Encrypt with export key
	encrypted, err := v.crypto.Encrypt(exportKey, exportData, []byte("file_export"))
	security.Zeroize(exportData)
	for _, chunk := range chunks {
		security.Zeroize(chunk)
	}

	return encrypted, err
}

type fileExport struct {
	Name         string         `json:"name"`
	OriginalName string         `json:"original_name"`
	ContentType  string         `json:"content_type"`
	Size         int64          `json:"size"`
	Hash         []byte         `json:"hash"`
	Chunks       [][]byte       `json:"chunks"`
	Metadata     types.Metadata `json:"metadata"`
}

// Import imports a file from export
func (v *Vault) Import(ctx context.Context, encryptedExport []byte, importKey []byte, importerID types.ID) (*types.EncryptedFile, error) {
	exportData, err := v.crypto.Decrypt(importKey, encryptedExport, []byte("file_export"))
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(exportData)

	var export fileExport
	if err := json.Unmarshal(exportData, &export); err != nil {
		return nil, err
	}

	// Create a reader from chunks
	reader := &chunkReader{chunks: export.Chunks}

	return v.Upload(ctx, UploadOptions{
		Name:         export.Name,
		OriginalName: export.OriginalName,
		ContentType:  export.ContentType,
		Reader:       reader,
		Metadata:     export.Metadata,
		UploaderID:   importerID,
	})
}

type chunkReader struct {
	chunks [][]byte
	pos    int
	offset int
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.chunks) {
		return 0, io.EOF
	}

	chunk := r.chunks[r.pos]
	remaining := chunk[r.offset:]
	n = copy(p, remaining)
	r.offset += n

	if r.offset >= len(chunk) {
		r.pos++
		r.offset = 0
	}

	return n, nil
}

// Close cleans up resources
func (v *Vault) Close() error {
	if v.protection != nil {
		_ = v.protection.Close()
	}
	return v.crypto.Close()
}

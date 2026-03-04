package files

import (
	"bytes"
	"context"
	"fmt"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Enhanced file manager with folder support
type EnhancedManager struct {
	*Vault
	auditEngine *audit.Engine
}

// NewEnhancedManager creates an enhanced file manager
func NewEnhancedManager(cfg VaultConfig, auditEngine *audit.Engine) *EnhancedManager {
	return &EnhancedManager{
		Vault:       NewVault(cfg),
		auditEngine: auditEngine,
	}
}

// UploadFolder uploads a folder as an encrypted archive with full audit trail
func (m *EnhancedManager) UploadFolder(ctx context.Context, opts UploadFolderOptions) (*types.EncryptedFile, error) {
	// Create audit entry for folder upload
	auditDetails := types.Metadata{
		"operation":    "folder_upload",
		"folder_path":  opts.FolderPath,
		"archive_size": len(opts.ArchiveData),
		"file_count":   opts.FileCount,
		"total_size":   opts.TotalSize,
	}

	// Use regular upload with enhanced metadata
	uploadOpts := UploadOptions{
		Name:        opts.Name,
		Reader:      bytes.NewReader(opts.ArchiveData),
		ContentType: "application/x-tar-gzip",
		UploaderID:  opts.CreatorID,
		Metadata: types.Metadata{
			"is_folder":   true,
			"folder_path": opts.FolderPath,
			"file_count":  opts.FileCount,
			"total_size":  opts.TotalSize,
			"operation":   opts.Operation, // lock, hide, envelope
		},
	}

	file, err := m.Vault.Upload(ctx, uploadOpts)
	if err != nil {
		return nil, err
	}

	// Log folder-specific audit event
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "folder",
			Action:       "upload",
			ActorID:      opts.CreatorID,
			ActorType:    "identity",
			ResourceID:   &file.ID,
			ResourceType: "folder",
			Success:      true,
			Details:      auditDetails,
		})
	}

	return file, nil
}

// DownloadFolder downloads and extracts a folder archive
func (m *EnhancedManager) DownloadFolder(ctx context.Context, name string, accessorID types.ID, mfaVerified bool) ([]byte, *types.EncryptedFile, error) {
	// Download the archive
	var buf bytes.Buffer
	err := m.Vault.Download(ctx, name, DownloadOptions{
		AccessorID:  accessorID,
		MFAVerified: mfaVerified,
	}, &buf)

	if err != nil {
		return nil, nil, err
	}
	data := buf.Bytes()

	// Get file metadata
	file, err := m.Vault.GetMetadata(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	// Verify it's a folder
	if isFolder, ok := file.Metadata["is_folder"].(bool); !ok || !isFolder {
		return nil, nil, fmt.Errorf("file is not a folder archive")
	}

	// Log folder-specific audit event
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "folder",
			Action:       "download",
			ActorID:      accessorID,
			ActorType:    "identity",
			ResourceID:   &file.ID,
			ResourceType: "folder",
			Success:      true,
			Details: types.Metadata{
				"operation":   "folder_download",
				"folder_name": name,
				"data_size":   len(data),
			},
		})
	}

	return data, file, nil
}

// ListFolders lists all folder archives
func (m *EnhancedManager) ListFolders(ctx context.Context, opts ListOptions) ([]*types.EncryptedFile, error) {
	files, err := m.Vault.List(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Filter for folders only
	folders := make([]*types.EncryptedFile, 0)
	for _, file := range files {
		if isFolder, ok := file.Metadata["is_folder"].(bool); ok && isFolder {
			folders = append(folders, file)
		}
	}

	return folders, nil
}

// GetFolderCustodyChain gets the custody chain for a folder
func (m *EnhancedManager) GetFolderCustodyChain(ctx context.Context, name string) ([]types.ProvenanceEntry, error) {
	file, err := m.Vault.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	// Verify it's a folder
	if isFolder, ok := file.Metadata["is_folder"].(bool); !ok || !isFolder {
		return nil, fmt.Errorf("file is not a folder archive")
	}

	// Return custody chain (provenance chain)
	if file.Provenance == nil {
		return nil, nil
	}
	return file.Provenance.Chain, nil
}

// UploadFolderOptions holds options for folder upload
type UploadFolderOptions struct {
	Name        string
	FolderPath  string
	ArchiveData []byte
	FileCount   int
	TotalSize   int64
	CreatorID   types.ID
	Operation   string // lock, hide, envelope
}

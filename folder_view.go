package velocity

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oarkflow/previewer"
	"github.com/oarkflow/previewer/pkg/vfs"
)

// ViewFolder retrieves a folder from vault and opens it in a secure in-memory sandbox
// No temporary files are created - everything stays in protected memory
func (db *DB) ViewFolder(folderPath, user string, compress bool, maxFileSize int64) error {
	// Use secure in-memory VFS - no disk writes
	return db.ViewFolderSecure(folderPath, user, compress, maxFileSize)
}

// ViewFolderLegacy is the legacy implementation that uses temporary directories
// DEPRECATED: Use ViewFolder (secure in-memory mode) instead
func (db *DB) ViewFolderLegacy(folderPath, user string, compress bool, maxFileSize int64) error {
	// Get folder from vault
	folder, err := db.GetFolder(folderPath)
	if err != nil {
		return fmt.Errorf("folder not found in vault: %w", err)
	}

	log.Printf("Found folder in vault: %s (LEGACY MODE - using temp files)", folder.Path)

	// Download folder contents to temporary directory
	tempDir, err := os.MkdirTemp("", "velocity-folder-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	// Ensure temp directory is cleaned up after preview completes
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			log.Printf("Warning: failed to clean up temp directory %s: %v", tempDir, removeErr)
		}
	}()

	// Set secure permissions on temp directory (owner read/write/execute only)
	if err := os.Chmod(tempDir, 0700); err != nil {
		log.Printf("Warning: failed to set secure permissions on temp directory: %v", err)
	}

	log.Printf("Extracting folder to: %s", tempDir)

	// Normalize folder path - ensure it doesn't have leading slash for prefix matching
	searchPrefix := folderPath
	if searchPrefix[0] == '/' {
		searchPrefix = searchPrefix[1:]
	}
	if searchPrefix != "" && searchPrefix[len(searchPrefix)-1] != '/' {
		searchPrefix += "/"
	}

	// List all objects in the folder recursively using Prefix
	objects, err := db.ListObjects(ObjectListOptions{
		Prefix:    searchPrefix,
		Recursive: true,
		MaxKeys:   10000,
	})
	if err != nil {
		return fmt.Errorf("failed to list folder contents: %w", err)
	}

	if len(objects) == 0 {
		log.Printf("Warning: Folder is empty")
		return fmt.Errorf("folder is empty: %s", folderPath)
	}

	log.Printf("Found %d objects in folder", len(objects))

	// Download each object to temp directory
	for _, obj := range objects {
		// Strip folder prefix from object path to avoid nesting
		relPath := obj.Path
		if len(relPath) > 0 && relPath[0] == '/' {
			relPath = relPath[1:]
		}
		// Remove the folder prefix
		if len(relPath) >= len(searchPrefix) && relPath[:len(searchPrefix)] == searchPrefix {
			relPath = relPath[len(searchPrefix):]
		}

		// Create subdirectory structure
		objectPath := filepath.Join(tempDir, relPath)
		objectDir := filepath.Dir(objectPath)

		if err := os.MkdirAll(objectDir, 0755); err != nil {
			log.Printf("Warning: failed to create directory %s: %v", objectDir, err)
			continue
		}

		// Get object data
		data, _, err := db.GetObject(obj.Path, user)
		if err != nil {
			log.Printf("Warning: failed to get object %s: %v", obj.Path, err)
			continue
		}

		// Write to file with secure permissions (owner read/write only)
		if err := os.WriteFile(objectPath, data, 0600); err != nil {
			log.Printf("Warning: failed to write file %s: %v", objectPath, err)
			continue
		}
	}

	log.Printf("All objects extracted successfully")

	// Build VFS from temp directory
	opts := vfs.Options{
		MaxFileSize:       maxFileSize,
		MaxTotalSize:      500 * 1024 * 1024, // 500MB default
		EnableCompression: compress,
		MaxAccessPerFile:  1000,
		AnomalyThreshold:  75,
		MLockMemory:       false,
	}
	return previewer.PreviewFolder(tempDir, opts)
}

// repeatString repeats a string n times
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

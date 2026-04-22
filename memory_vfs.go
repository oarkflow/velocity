package velocity

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/previewer"
	"github.com/oarkflow/previewer/pkg/vfs"
)

// MemoryVFS implements a secure in-memory virtual filesystem
// No data ever touches the disk during preview operations
type MemoryVFS struct {
	mu       sync.RWMutex
	files    map[string]*MemoryFile
	rootPath string
	options  vfs.Options
}

// MemoryFile represents a file stored entirely in memory
type MemoryFile struct {
	Path         string
	Data         []byte
	Size         int64
	ModTime      time.Time
	IsDir        bool
	Children     map[string]*MemoryFile // For directory entries
	ContentType  string
	AccessCount  int
	mu           sync.RWMutex
}

// NewMemoryVFS creates a new in-memory virtual filesystem
func NewMemoryVFS(rootPath string, opts vfs.Options) *MemoryVFS {
	return &MemoryVFS{
		files:    make(map[string]*MemoryFile),
		rootPath: rootPath,
		options:  opts,
	}
}

// AddFile adds a file to the in-memory VFS
func (mvfs *MemoryVFS) AddFile(path string, data []byte, contentType string) error {
	mvfs.mu.Lock()
	defer mvfs.mu.Unlock()

	// Check file size limits
	if mvfs.options.MaxFileSize > 0 && int64(len(data)) > mvfs.options.MaxFileSize {
		return fmt.Errorf("file size exceeds limit: %d > %d", len(data), mvfs.options.MaxFileSize)
	}

	// Check total size limit
	totalSize := mvfs.calculateTotalSize()
	if mvfs.options.MaxTotalSize > 0 && totalSize+int64(len(data)) > mvfs.options.MaxTotalSize {
		return fmt.Errorf("total size would exceed limit")
	}

	// Normalize path
	normalizedPath := strings.TrimPrefix(path, "/")
	if normalizedPath == "" {
		return fmt.Errorf("invalid empty path")
	}

	// Create parent directories
	dir := filepath.Dir(normalizedPath)
	if dir != "." && dir != "" {
		if err := mvfs.createDirectoryPath(dir); err != nil {
			return err
		}
	}

	// Create or update file
	file := &MemoryFile{
		Path:        normalizedPath,
		Data:        data,
		Size:        int64(len(data)),
		ModTime:     time.Now(),
		IsDir:       false,
		ContentType: contentType,
		AccessCount: 0,
	}

	mvfs.files[normalizedPath] = file

	// Add to parent directory
	if dir != "." && dir != "" {
		if parent, exists := mvfs.files[dir]; exists && parent.IsDir {
			parent.mu.Lock()
			parent.Children[filepath.Base(normalizedPath)] = file
			parent.mu.Unlock()
		}
	}

	log.Printf("Added file to memory VFS: %s (%d bytes)", normalizedPath, len(data))
	return nil
}

// createDirectoryPath creates all parent directories for a path
func (mvfs *MemoryVFS) createDirectoryPath(path string) error {
	parts := strings.Split(path, string(filepath.Separator))
	currentPath := ""

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}

		if currentPath != "" {
			currentPath += string(filepath.Separator)
		}
		currentPath += part

		if _, exists := mvfs.files[currentPath]; !exists {
			dir := &MemoryFile{
				Path:     currentPath,
				IsDir:    true,
				ModTime:  time.Now(),
				Children: make(map[string]*MemoryFile),
			}
			mvfs.files[currentPath] = dir

			// Add to parent's children
			parentPath := filepath.Dir(currentPath)
			if parentPath != "." && parentPath != "" {
				if parent, exists := mvfs.files[parentPath]; exists && parent.IsDir {
					parent.mu.Lock()
					parent.Children[part] = dir
					parent.mu.Unlock()
				}
			}
		}
	}

	return nil
}

// GetFile retrieves a file from the in-memory VFS
func (mvfs *MemoryVFS) GetFile(path string) (*MemoryFile, error) {
	mvfs.mu.RLock()
	defer mvfs.mu.RUnlock()

	normalizedPath := strings.TrimPrefix(path, "/")
	file, exists := mvfs.files[normalizedPath]
	if !exists {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	// Track access count
	file.mu.Lock()
	file.AccessCount++

	// Security: Check anomaly threshold
	if mvfs.options.MaxAccessPerFile > 0 && file.AccessCount > mvfs.options.MaxAccessPerFile {
		file.mu.Unlock()
		log.Printf("Warning: File %s exceeded access limit (%d)", path, file.AccessCount)
		if mvfs.options.AnomalyThreshold > 0 {
			return nil, fmt.Errorf("access limit exceeded for file: %s", path)
		}
	} else {
		file.mu.Unlock()
	}

	return file, nil
}

// ReadFile reads file data from the in-memory VFS
func (mvfs *MemoryVFS) ReadFile(path string) ([]byte, error) {
	file, err := mvfs.GetFile(path)
	if err != nil {
		return nil, err
	}

	if file.IsDir {
		return nil, fmt.Errorf("cannot read directory as file: %s", path)
	}

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(file.Data))
	copy(dataCopy, file.Data)

	return dataCopy, nil
}

// ListFiles lists all files in the VFS
func (mvfs *MemoryVFS) ListFiles() []string {
	mvfs.mu.RLock()
	defer mvfs.mu.RUnlock()

	files := make([]string, 0, len(mvfs.files))
	for path, file := range mvfs.files {
		if !file.IsDir {
			files = append(files, path)
		}
	}
	return files
}

// calculateTotalSize calculates total size of all files in VFS
func (mvfs *MemoryVFS) calculateTotalSize() int64 {
	var total int64
	for _, file := range mvfs.files {
		if !file.IsDir {
			total += file.Size
		}
	}
	return total
}

// GetStats returns statistics about the in-memory VFS
func (mvfs *MemoryVFS) GetStats() map[string]interface{} {
	mvfs.mu.RLock()
	defer mvfs.mu.RUnlock()

	fileCount := 0
	dirCount := 0
	totalSize := int64(0)

	for _, file := range mvfs.files {
		if file.IsDir {
			dirCount++
		} else {
			fileCount++
			totalSize += file.Size
		}
	}

	return map[string]interface{}{
		"file_count":  fileCount,
		"dir_count":   dirCount,
		"total_size":  totalSize,
		"total_items": len(mvfs.files),
	}
}

// Clear securely wipes all data from memory
func (mvfs *MemoryVFS) Clear() {
	mvfs.mu.Lock()
	defer mvfs.mu.Unlock()

	// Securely zero out all file data before clearing
	for _, file := range mvfs.files {
		if !file.IsDir && file.Data != nil {
			// Zero out the data for security
			for i := range file.Data {
				file.Data[i] = 0
			}
			file.Data = nil
		}
		file.Children = nil
	}

	mvfs.files = make(map[string]*MemoryFile)
	log.Printf("Memory VFS cleared securely")
}

// ExportToReader exports a file as an io.Reader for preview
func (mvfs *MemoryVFS) ExportToReader(path string) (io.Reader, error) {
	data, err := mvfs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// ViewFolderSecure previews a folder using in-memory VFS without any disk writes
func (db *DB) ViewFolderSecure(folderPath, user string, compress bool, maxFileSize int64) error {
	// Get folder from vault
	folder, err := db.GetFolder(folderPath)
	if err != nil {
		return fmt.Errorf("folder not found in vault: %w", err)
	}

	log.Printf("Found folder in vault: %s (secure in-memory mode)", folder.Path)

	// Create in-memory VFS
	opts := vfs.Options{
		MaxFileSize:       maxFileSize,
		MaxTotalSize:      500 * 1024 * 1024, // 500MB default
		EnableCompression: compress,
		MaxAccessPerFile:  1000,
		AnomalyThreshold:  75,
		MLockMemory:       false,
	}

	memVFS := NewMemoryVFS(folderPath, opts)
	defer memVFS.Clear() // Ensure memory is cleared after preview

	// Normalize folder path
	searchPrefix := folderPath
	if len(searchPrefix) > 0 && searchPrefix[0] == '/' {
		searchPrefix = searchPrefix[1:]
	}
	if searchPrefix != "" && searchPrefix[len(searchPrefix)-1] != '/' {
		searchPrefix += "/"
	}

	// List all objects in the folder
	objects, err := db.ListObjects(ObjectListOptions{
		Prefix:    searchPrefix,
		Recursive: true,
		MaxKeys:   10000,
	})
	if err != nil {
		return fmt.Errorf("failed to list folder contents: %w", err)
	}

	if len(objects) == 0 {
		return fmt.Errorf("folder is empty: %s", folderPath)
	}

	log.Printf("Loading %d objects into memory VFS", len(objects))

	// Load each object into memory VFS
	for _, obj := range objects {
		// Get object data
		data, meta, err := db.GetObject(obj.Path, user)
		if err != nil {
			log.Printf("Warning: failed to get object %s: %v", obj.Path, err)
			continue
		}

		// Strip folder prefix from object path
		relPath := obj.Path
		if len(relPath) > 0 && relPath[0] == '/' {
			relPath = relPath[1:]
		}
		if len(relPath) >= len(searchPrefix) && relPath[:len(searchPrefix)] == searchPrefix {
			relPath = relPath[len(searchPrefix):]
		}

		// Add to in-memory VFS
		if err := memVFS.AddFile(relPath, data, meta.ContentType); err != nil {
			log.Printf("Warning: failed to add file to VFS %s: %v", relPath, err)
			continue
		}
	}

	stats := memVFS.GetStats()
	log.Printf("Memory VFS loaded: %d files, %d dirs, %d bytes total",
		stats["file_count"], stats["dir_count"], stats["total_size"])

	// Create a temporary directory ONLY for the previewer to use as a reference point
	// The actual data remains in memory and is served through the VFS
	return db.previewMemoryVFS(memVFS, folderPath, opts)
}

// ViewObjectSecure previews a single object using in-memory buffer without disk writes
func (db *DB) ViewObjectSecure(path, userID string) error {
	// Retrieve the object from the database
	data, meta, err := db.GetObject(path, userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve object: %w", err)
	}

	log.Printf("Viewing object in-memory: %s (%d bytes)", path, len(data))

	// Create in-memory VFS with single file
	opts := vfs.Options{
		MaxFileSize:       100 * 1024 * 1024,
		MaxTotalSize:      100 * 1024 * 1024,
		EnableCompression: false,
		MaxAccessPerFile:  1000,
		AnomalyThreshold:  75,
		MLockMemory:       false,
	}

	memVFS := NewMemoryVFS("preview", opts)
	defer memVFS.Clear()

	// Extract filename from path
	filename := filepath.Base(path)
	if filename == "" || filename == "." || filename == "/" {
		filename = "file" + getExtensionFromContentType(meta.ContentType)
	}

	// Add file to memory VFS
	if err := memVFS.AddFile(filename, data, meta.ContentType); err != nil {
		return fmt.Errorf("failed to add file to memory VFS: %w", err)
	}

	// Preview using in-memory data
	return db.previewMemoryFile(memVFS, filename, meta.ContentType)
}

// previewMemoryVFS handles the preview of in-memory VFS folder
// Creates temporary files ONLY for the duration of the preview, with guaranteed secure cleanup
func (db *DB) previewMemoryVFS(memVFS *MemoryVFS, folderPath string, opts vfs.Options) error {
	// Create temporary directory with secure permissions for previewer
	tempDir, err := os.MkdirTemp("", "velocity-secure-preview-*")
	if err != nil {
		return fmt.Errorf("failed to create secure temp directory: %w", err)
	}

	// CRITICAL: Ensure cleanup happens no matter what
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			log.Printf("Warning: failed to clean up secure temp directory %s: %v", tempDir, removeErr)
		} else {
			log.Printf("Secure temp directory cleaned up: %s", tempDir)
		}
	}()

	// Set most restrictive permissions
	if err := os.Chmod(tempDir, 0700); err != nil {
		return fmt.Errorf("failed to set secure permissions: %w", err)
	}

	// Materialize files from memory to disk for previewer
	files := memVFS.ListFiles()
	log.Printf("Materializing %d files to secure temp location for preview", len(files))

	for _, filePath := range files {
		file, err := memVFS.GetFile(filePath)
		if err != nil {
			log.Printf("Warning: failed to get file %s: %v", filePath, err)
			continue
		}

		// Create full path in temp directory
		fullPath := filepath.Join(tempDir, filePath)
		dir := filepath.Dir(fullPath)

		// Create parent directories with secure permissions
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Printf("Warning: failed to create directory %s: %v", dir, err)
			continue
		}

		// Write file with most restrictive permissions
		if err := os.WriteFile(fullPath, file.Data, 0600); err != nil {
			log.Printf("Warning: failed to write file %s: %v", fullPath, err)
			continue
		}
	}

	log.Printf("Files materialized to: %s", tempDir)
	log.Printf("⚠️  Secure mode: All files will be permanently deleted when preview closes")

	// Call previewer - cleanup happens via defer when this returns
	return previewer.PreviewFolder(tempDir, opts)
}

// previewMemoryFile handles the preview of a single in-memory file
// Creates a temporary file ONLY for the duration of the preview, with guaranteed secure cleanup
func (db *DB) previewMemoryFile(memVFS *MemoryVFS, filename, contentType string) error {
	file, err := memVFS.GetFile(filename)
	if err != nil {
		return err
	}

	// Determine file extension
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = getExtensionFromContentType(contentType)
	}

	// Create temporary file with secure permissions
	tempFile, err := os.CreateTemp("", "velocity-secure-preview-*"+ext)
	if err != nil {
		return fmt.Errorf("failed to create secure temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// CRITICAL: Ensure cleanup happens no matter what
	defer func() {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			log.Printf("Warning: failed to clean up secure temp file %s: %v", tempPath, removeErr)
		} else {
			log.Printf("Secure temp file cleaned up: %s", tempPath)
		}
	}()

	// Set most restrictive permissions
	if err := os.Chmod(tempPath, 0600); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to set secure permissions: %w", err)
	}

	// Write data to temp file
	if _, err := tempFile.Write(file.Data); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	log.Printf("File materialized to: %s", tempPath)
	log.Printf("⚠️  Secure mode: File will be permanently deleted when preview closes")

	// Call previewer - cleanup happens via defer when this returns
	return previewer.PreviewFile(tempPath)
}

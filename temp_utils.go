package velocity

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// TempResource represents a temporary file or directory that will be cleaned up
type TempResource struct {
	Path      string
	IsDir     bool
	cleanupFn func() error
}

// TempManager manages temporary files and directories with automatic cleanup
type TempManager struct {
	mu        sync.Mutex
	resources []*TempResource
}

// NewTempManager creates a new temporary resource manager
func NewTempManager() *TempManager {
	return &TempManager{
		resources: make([]*TempResource, 0),
	}
}

// CreateSecureTempDir creates a temporary directory with secure permissions (0700)
// The directory will be automatically tracked for cleanup
func (tm *TempManager) CreateSecureTempDir(pattern string) (string, error) {
	tempDir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Set secure permissions (owner read/write/execute only)
	if err := os.Chmod(tempDir, 0700); err != nil {
		os.RemoveAll(tempDir) // Clean up on error
		return "", fmt.Errorf("failed to set secure permissions: %w", err)
	}

	tm.track(tempDir, true)
	return tempDir, nil
}

// CreateSecureTempFile creates a temporary file with secure permissions (0600)
// The file will be automatically tracked for cleanup
func (tm *TempManager) CreateSecureTempFile(pattern string) (*os.File, error) {
	tempFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Set secure permissions (owner read/write only)
	if err := os.Chmod(tempFile.Name(), 0600); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to set secure permissions: %w", err)
	}

	tm.track(tempFile.Name(), false)
	return tempFile, nil
}

// track adds a resource to the cleanup list
func (tm *TempManager) track(path string, isDir bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	resource := &TempResource{
		Path:  path,
		IsDir: isDir,
	}

	if isDir {
		resource.cleanupFn = func() error {
			return os.RemoveAll(path)
		}
	} else {
		resource.cleanupFn = func() error {
			return os.Remove(path)
		}
	}

	tm.resources = append(tm.resources, resource)
}

// Cleanup removes all tracked temporary resources
// This should be called with defer to ensure cleanup happens
func (tm *TempManager) Cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, resource := range tm.resources {
		if err := resource.cleanupFn(); err != nil {
			log.Printf("Warning: failed to clean up temp resource %s: %v", resource.Path, err)
		}
	}

	tm.resources = nil
}

// CleanupPath removes a specific tracked resource early
func (tm *TempManager) CleanupPath(path string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for i, resource := range tm.resources {
		if resource.Path == path {
			err := resource.cleanupFn()
			// Remove from tracking list
			tm.resources = append(tm.resources[:i], tm.resources[i+1:]...)
			return err
		}
	}

	return fmt.Errorf("resource not found: %s", path)
}

// Count returns the number of tracked temporary resources
func (tm *TempManager) Count() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.resources)
}

// SecureWriteFile writes data to a file with secure permissions
func SecureWriteFile(path string, data []byte) error {
	// Create parent directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with secure permissions (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// CleanupOrphanedTempFiles removes orphaned temporary files/directories
// matching common velocity temporary patterns
func CleanupOrphanedTempFiles() error {
	tempDir := os.TempDir()

	patterns := []string{
		"velocity-folder-*",
		"velocity-preview-*",
	}

	var cleanupErrors []error

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(tempDir, pattern))
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("glob error for pattern %s: %w", pattern, err))
			continue
		}

		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}

			var removeErr error
			if info.IsDir() {
				removeErr = os.RemoveAll(match)
			} else {
				removeErr = os.Remove(match)
			}

			if removeErr != nil {
				log.Printf("Warning: failed to remove orphaned temp resource %s: %v", match, removeErr)
				cleanupErrors = append(cleanupErrors, removeErr)
			} else {
				log.Printf("Cleaned up orphaned temp resource: %s", match)
			}
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("encountered %d errors during orphaned temp cleanup", len(cleanupErrors))
	}

	return nil
}

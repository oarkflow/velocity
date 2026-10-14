// Package preview opens a single object, or every object under a key prefix,
// in the previewer viewer. Data is materialised into a private temporary
// location that is removed as soon as the viewer returns.
package preview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/oarkflow/previewer"
	"github.com/oarkflow/previewer/pkg/vfs"

	"github.com/oarkflow/velocity/v2/api"
)

// maxFolderObjects bounds how many objects a single folder preview may load.
const maxFolderObjects = 10000

// Defaults applied when FolderOptions leaves a limit at zero. The viewer treats
// a zero limit literally, so zero must never reach it.
const (
	defaultMaxFileSize  = 100 * 1024 * 1024
	defaultMaxTotalSize = 500 * 1024 * 1024
)

// Indirections so tests can exercise materialisation without launching the
// blocking viewer.
var (
	previewFile   = previewer.PreviewFile
	previewFolder = func(dir string, opts vfs.Options) error {
		return previewer.PreviewFolder(dir, opts)
	}
)

// Reader is the subset of api.ObjectService that previews need.
type Reader interface {
	GetObject(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, api.ObjectMeta, error)
	ListObjects(ctx context.Context, bucket, prefix string) ([]api.ObjectMeta, error)
}

// FolderOptions controls a folder preview.
type FolderOptions struct {
	// MaxFileSize caps each file; zero uses 100MB.
	MaxFileSize int64
	// MaxTotalSize caps the combined size; zero uses 500MB.
	MaxTotalSize int64
	// Compress enables the viewer's compression.
	Compress bool
}

// ViewObject previews the latest version of bucket/key.
func ViewObject(ctx context.Context, store Reader, bucket, key string) error {
	rc, meta, err := store.GetObject(ctx, bucket, key, "")
	if err != nil {
		return fmt.Errorf("failed to retrieve object: %w", err)
	}
	defer rc.Close()

	ext := path.Ext(key)
	if ext == "" {
		ext = extensionForContentType(meta.ContentType)
	}

	f, err := os.CreateTemp("", "velocity-preview-*"+ext)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := f.Name()
	defer func() {
		if rmErr := os.Remove(tempPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			log.Printf("Warning: failed to clean up temp file %s: %v", tempPath, rmErr)
		}
	}()

	if err := f.Chmod(0600); err != nil {
		f.Close()
		return fmt.Errorf("failed to set secure permissions on temp file: %w", err)
	}
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	return previewFile(tempPath)
}

// ViewFolder previews every object whose key starts with prefix. The prefix
// is treated as a folder: a trailing "/" is added when missing.
func ViewFolder(ctx context.Context, store Reader, bucket, prefix string, opts FolderOptions) error {
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	objects, err := store.ListObjects(ctx, bucket, prefix)
	if err != nil {
		return fmt.Errorf("failed to list folder contents: %w", err)
	}
	if len(objects) == 0 {
		return fmt.Errorf("folder is empty: %s", prefix)
	}
	if len(objects) > maxFolderObjects {
		return fmt.Errorf("folder has more than %d objects: %s", maxFolderObjects, prefix)
	}

	maxFile := opts.MaxFileSize
	if maxFile <= 0 {
		maxFile = defaultMaxFileSize
	}
	maxTotal := opts.MaxTotalSize
	if maxTotal <= 0 {
		maxTotal = defaultMaxTotalSize
	}
	var total int64
	for _, obj := range objects {
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}
		if obj.Size > maxFile {
			return fmt.Errorf("object %s exceeds max file size (%d > %d bytes)", obj.Key, obj.Size, maxFile)
		}
		total += obj.Size
	}
	if total > maxTotal {
		return fmt.Errorf("folder exceeds max total size (%d > %d bytes)", total, maxTotal)
	}

	tempDir, err := os.MkdirTemp("", "velocity-folder-preview-*")
	if err != nil {
		return fmt.Errorf("failed to create secure temp directory: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			log.Printf("Warning: failed to clean up temp directory %s: %v", tempDir, rmErr)
		}
	}()
	if err := os.Chmod(tempDir, 0700); err != nil {
		return fmt.Errorf("failed to set secure permissions: %w", err)
	}

	for _, obj := range objects {
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}
		rel := strings.TrimPrefix(obj.Key, prefix)
		dst, err := safeJoin(tempDir, rel)
		if err != nil {
			return fmt.Errorf("object %s: %w", obj.Key, err)
		}
		if err := materialise(ctx, store, bucket, obj.Key, dst); err != nil {
			return err
		}
	}

	vopts := vfs.Options{
		MaxFileSize:       maxFile,
		MaxTotalSize:      maxTotal,
		EnableCompression: opts.Compress,
		MaxAccessPerFile:  1000,
		AnomalyThreshold:  75,
		MLockMemory:       false,
	}
	return previewFolder(tempDir, vopts)
}

// materialise copies one object to dst, creating parent directories.
func materialise(ctx context.Context, store Reader, bucket, key, dst string) error {
	rc, _, err := store.GetObject(ctx, bucket, key, "")
	if err != nil {
		return fmt.Errorf("failed to get object %s: %w", key, err)
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", key, err)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file for %s: %w", key, err)
	}
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return fmt.Errorf("failed to write %s: %w", key, err)
	}
	return f.Close()
}

// safeJoin joins rel under root and rejects anything that would escape it,
// such as keys containing "..", absolute paths or empty names.
func safeJoin(root, rel string) (string, error) {
	cleaned := filepath.Clean(filepath.FromSlash(rel))
	if cleaned == "." || cleaned == "" || filepath.IsAbs(cleaned) ||
		cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe relative path %q", rel)
	}
	return filepath.Join(root, cleaned), nil
}

// extensionForContentType maps common content types to a file extension.
func extensionForContentType(contentType string) string {
	extensionMap := map[string]string{
		"text/plain":               ".txt",
		"text/html":                ".html",
		"text/css":                 ".css",
		"text/javascript":          ".js",
		"text/markdown":            ".md",
		"application/json":         ".json",
		"application/xml":          ".xml",
		"application/pdf":          ".pdf",
		"application/zip":          ".zip",
		"image/png":                ".png",
		"image/jpeg":               ".jpg",
		"image/gif":                ".gif",
		"image/svg+xml":            ".svg",
		"video/mp4":                ".mp4",
		"audio/mpeg":               ".mp3",
		"text/x-shellscript":       ".sh",
		"application/x-sh":         ".sh",
		"text/x-python":            ".py",
		"text/x-go":                ".go",
		"application/octet-stream": ".bin",
	}
	if ext, ok := extensionMap[contentType]; ok {
		return ext
	}
	return ".txt"
}

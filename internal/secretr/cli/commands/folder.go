package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

func FolderLock(ctx context.Context, cmd *cli.Command) error {
	folderPath := cmd.String("path")
	name := cmd.String("name")
	
	if name == "" {
		name = filepath.Base(folderPath) + ".locked"
	}

	// Get folder stats
	fileCount, totalSize, err := getFolderStats(folderPath)
	if err != nil {
		return fmt.Errorf("failed to analyze folder: %w", err)
	}

	// Create tar.gz of folder
	archiveData, err := createFolderArchive(folderPath)
	if err != nil {
		return fmt.Errorf("failed to archive folder: %w", err)
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Upload as encrypted file with folder metadata
	reader := &bytesReader{data: archiveData}
	_, err = c.Files.Upload(ctx, files.UploadOptions{
		Name:              name,
		OriginalName:      folderPath,
		ContentType:       "application/x-tar-gzip",
		Reader:            reader,
		UploaderID:        c.CurrentIdentityID(),
		DeviceFingerprint: "folder-lock",
		Metadata: types.Metadata{
			"is_folder":   true,
			"folder_path": folderPath,
			"file_count":  fileCount,
			"total_size":  totalSize,
			"operation":   "lock",
		},
	})
	if err != nil {
		return err
	}

	success("Folder locked and encrypted: %s -> %s", folderPath, name)
	info("Files: %d, Total size: %d bytes", fileCount, totalSize)
	return nil
}

func FolderUnlock(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Download encrypted file
	buf := &bytesWriter{}
	err = c.Files.Download(ctx, name, files.DownloadOptions{
		AccessorID:  c.CurrentIdentityID(),
		MFAVerified: false,
	}, buf)
	if err != nil {
		return err
	}

	// Extract archive
	if err := extractFolderArchive(buf.data, outputPath); err != nil {
		return fmt.Errorf("failed to extract folder: %w", err)
	}

	success("Folder unlocked: %s -> %s", name, outputPath)
	return nil
}

func FolderHide(ctx context.Context, cmd *cli.Command) error {
	folderPath := cmd.String("path")
	name := cmd.String("name")
	
	if name == "" {
		name = filepath.Base(folderPath) + ".hidden"
	}

	// Get folder stats
	fileCount, totalSize, err := getFolderStats(folderPath)
	if err != nil {
		return fmt.Errorf("failed to analyze folder: %w", err)
	}

	// Create tar.gz of folder
	archiveData, err := createFolderArchive(folderPath)
	if err != nil {
		return fmt.Errorf("failed to archive folder: %w", err)
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Upload as encrypted file
	reader := &bytesReader{data: archiveData}
	_, err = c.Files.Upload(ctx, files.UploadOptions{
		Name:              name,
		OriginalName:      folderPath,
		ContentType:       "application/x-tar-gzip",
		Reader:            reader,
		UploaderID:        c.CurrentIdentityID(),
		DeviceFingerprint: "folder-hide",
		Metadata: types.Metadata{
			"is_folder":   true,
			"folder_path": folderPath,
			"file_count":  fileCount,
			"total_size":  totalSize,
			"operation":   "hide",
		},
	})
	if err != nil {
		return err
	}

	// Remove original folder
	if err := os.RemoveAll(folderPath); err != nil {
		return fmt.Errorf("failed to remove original folder: %w", err)
	}

	success("Folder hidden and encrypted: %s -> %s", folderPath, name)
	info("Files: %d, Total size: %d bytes", fileCount, totalSize)
	return nil
}

func FolderShow(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Download encrypted file
	buf := &bytesWriter{}
	err = c.Files.Download(ctx, name, files.DownloadOptions{
		AccessorID:  c.CurrentIdentityID(),
		MFAVerified: false,
	}, buf)
	if err != nil {
		return err
	}

	// Extract archive
	if err := extractFolderArchive(buf.data, outputPath); err != nil {
		return fmt.Errorf("failed to extract folder: %w", err)
	}

	success("Folder restored: %s -> %s", name, outputPath)
	return nil
}

// Helper types
type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

type bytesWriter struct {
	data []byte
}

func (w *bytesWriter) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

// createFolderArchive creates a tar.gz archive of a folder
func createFolderArchive(folderPath string) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(folderPath, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tw, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	tw.Close()
	gw.Close()

	return buf.Bytes(), nil
}

// extractFolderArchive extracts a tar.gz archive to a folder
func extractFolderArchive(data []byte, outputPath string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(outputPath, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			_, err = io.Copy(file, tr)
			file.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// getFolderStats analyzes folder and returns file count and total size
func getFolderStats(folderPath string) (int, int64, error) {
	fileCount := 0
	var totalSize int64

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			fileCount++
			totalSize += info.Size()
		}
		return nil
	})

	return fileCount, totalSize, err
}
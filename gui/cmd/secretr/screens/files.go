package screens

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type FilesScreen struct {
	window   fyne.Window
	client   *cli.Client
	list     *widget.List
	data     []*types.EncryptedFile
	filtered []*types.EncryptedFile
}

func NewFilesScreen(w fyne.Window, client *cli.Client) *FilesScreen {
	return &FilesScreen{
		window: w,
		client: client,
	}
}

func (s *FilesScreen) Layout() fyne.CanvasObject {
	// Toolbar
	toolbar := container.NewHBox(
		widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), s.refreshData),
		widget.NewButtonWithIcon("Upload File", theme.UploadIcon(), s.showUploadDialog),
	)

	// List
	s.list = widget.NewList(
		func() int { return len(s.filtered) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.FileIcon()),
				widget.NewLabel("File Name"),
				widget.NewLabel("Size"),
			)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			if id >= len(s.filtered) {
				return
			}
			file := s.filtered[id]
			box := o.(*fyne.Container)
			box.Objects[1].(*widget.Label).SetText(file.Name)
			box.Objects[2].(*widget.Label).SetText(fmt.Sprintf("%d bytes", file.Size))
		},
	)

	s.list.OnSelected = func(id widget.ListItemID) {
		if id < len(s.filtered) {
			s.showDetails(s.filtered[id])
			s.list.Unselect(id)
		}
	}

	// Initial load
	s.refreshData()

	return container.NewBorder(toolbar, nil, nil, nil, s.list)
}

func (s *FilesScreen) refreshData() {
	ctx := context.Background()

	opts := files.ListOptions{}

	if err := s.client.RequireScope(types.ScopeFileList); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	fileList, err := s.client.Files.List(ctx, opts)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to list files: %v", err), s.window)
		return
	}

	s.data = fileList
	s.filtered = fileList
	s.list.Refresh()
}

func (s *FilesScreen) showUploadDialog() {
	fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, s.window)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()

		s.uploadFile(reader)
	}, s.window)

	fd.Show()
}

func (s *FilesScreen) uploadFile(reader fyne.URIReadCloser) {
	ctx := context.Background()

	if err := s.client.RequireScope(types.ScopeFileUpload); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	name := reader.URI().Name()

	// Copy to temp file because Upload expects os.File or io.ReadSeeker sometimes
	// or we can just pass reader if supported. internal/core/files/vault.go Upload takes UploadOptions
	// check internal/cli/commands/file.go: it passes f (os.File).

	// Let's create a temp file to be safe and ensure we have a standard reader
	tmpFile, err := os.CreateTemp("", "secretr-upload-*")
	if err != nil {
		dialog.ShowError(err, s.window)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, reader)
	if err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	_, err = s.client.Files.Upload(ctx, files.UploadOptions{
		Name:         name,
		OriginalName: name,
		Reader:       tmpFile,
		UploaderID:   s.client.CurrentIdentityID(),
		Overwrite:    true,
	})

	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to upload: %v", err), s.window)
		return
	}

	dialog.ShowInformation("Success", "File uploaded successfully", s.window)
	s.refreshData()
}

func (s *FilesScreen) showDetails(file *types.EncryptedFile) {
	downloadBtn := widget.NewButtonWithIcon("Download", theme.DownloadIcon(), func() {
		s.downloadFile(file)
	})

	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Delete File", "Delete "+file.Name+"?", func(b bool) {
			if b {
				s.deleteFile(file.Name)
			}
		}, s.window)
	})
	deleteBtn.Importance = widget.DangerImportance

	content := container.NewVBox(
		widget.NewLabelWithStyle("Name: "+file.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("Size: %d bytes", file.Size)),
		widget.NewLabel(fmt.Sprintf("Created: %s", file.CreatedAt.Time().Format(time.RFC3339))),
		widget.NewSeparator(),
		container.NewHBox(downloadBtn, deleteBtn),
	)

	d := dialog.NewCustom("File Details", "Close", content, s.window)
	d.Resize(fyne.NewSize(300, 200))
	d.Show()
}

func (s *FilesScreen) downloadFile(file *types.EncryptedFile) {
	fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, s.window)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()

		s.performDownload(file.Name, writer)
	}, s.window)

	fd.SetFileName(file.Name)
	fd.Show()
}

func (s *FilesScreen) performDownload(name string, writer fyne.URIWriteCloser) {
	ctx := context.Background()

	if err := s.client.RequireScope(types.ScopeFileDownload); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	// Create temp file for download output, then copy to writer
	// Or pass a pipe?
	// Client.Files.Download takes an io.Writer. URIWriteCloser is an io.Writer.

	// However, Files.Download might assume local file system optimizations or seeking?
	// Let's look at `internal/core/files/vault.go`. If it just copies, it's fine.

	// For safety with Fyne URIs (which might be slow or network based), let's just write directly.

	err := s.client.Files.Download(ctx, name, files.DownloadOptions{
		AccessorID:  s.client.CurrentIdentityID(),
		IPAddress:   "127.0.0.1",
		MFAVerified: s.client.CurrentSession() != nil && s.client.CurrentSession().MFAVerified,
	}, writer)

	if err != nil {
		dialog.ShowError(fmt.Errorf("Download failed: %v", err), s.window)
		return
	}

	dialog.ShowInformation("Success", "File downloaded successfully", s.window)
}

func (s *FilesScreen) deleteFile(name string) {
	ctx := context.Background()

	if err := s.client.RequireScope(types.ScopeFileDelete); err != nil {
		dialog.ShowError(err, s.window)
		return
	}

	if err := s.client.Files.Delete(ctx, name, s.client.CurrentIdentityID()); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to delete file: %v", err), s.window)
		return
	}

	s.refreshData()
}

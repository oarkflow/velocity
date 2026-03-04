package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/previewer"
	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// PreviewFile previews a file using the oarkflow/previewer
func PreviewFile(filePath string, originalName string) error {
	// Show file info header
	info, err := os.Stat(filePath)
	if err == nil {
		fmt.Printf("\n┌─────────────────────────────────────────────────────────────\n")
		fmt.Printf("│ File: %s\n", originalName)
		fmt.Printf("│ Size: %d bytes\n", info.Size())
		fmt.Printf("└─────────────────────────────────────────────────────────────\n\n")
	}

	// Use previewer to show the file
	return previewer.PreviewFile(filePath)
}

// PreviewReader previews content from a reader
func PreviewReader(r io.Reader) error {
	if r == nil {
		return fmt.Errorf("reader is nil")
	}
	return previewer.Preview(r)
}

// File commands

func FileUpload(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	path := cmd.String("path")
	expiresIn := cmd.Duration("expires-in")
	overwrite := cmd.Bool("overwrite")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileUpload); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	if name == "" {
		name = filepath.Base(path)
	}

	file, err := c.Files.Upload(ctx, files.UploadOptions{
		Name:         name,
		OriginalName: filepath.Base(path),
		Reader:       f,
		ExpiresIn:    expiresIn,
		Overwrite:    overwrite,
		UploaderID:   c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	success("File uploaded: %s (Size: %d)", file.Name, stat.Size())
	return nil
}

func FileDownload(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileDownload); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := c.Files.Download(ctx, name, files.DownloadOptions{
		AccessorID:  c.CurrentIdentityID(),
		IPAddress:   "127.0.0.1", // CLI is local
		MFAVerified: c.CurrentSession() != nil && c.CurrentSession().MFAVerified,
	}, f); err != nil {
		return err
	}

	success("File downloaded to %s", outputPath)
	return nil
}

func FileView(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileDownload); err != nil {
		return err
	}

	// Create temporary file for preview
	tmpFile, err := os.CreateTemp("", "secretr-preview-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up temp file after preview

	// Download to temp file
	if err := c.Files.Download(ctx, name, files.DownloadOptions{
		AccessorID:  c.CurrentIdentityID(),
		IPAddress:   "127.0.0.1",
		MFAVerified: c.CurrentSession() != nil && c.CurrentSession().MFAVerified,
	}, tmpFile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to download file: %w", err)
	}
	tmpFile.Close()

	// Preview the file
	if err := PreviewFile(tmpPath, name); err != nil {
		return fmt.Errorf("failed to preview file: %w", err)
	}

	return nil
}

func FileList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileList); err != nil {
		return err
	}

	fileList, err := c.Files.List(ctx, files.ListOptions{})
	if err != nil {
		return err
	}

	return output(cmd, fileList)
}

func FileDelete(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileDelete); err != nil {
		return err
	}

	if err := c.Files.Delete(ctx, name, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("File deleted: %s", name)
	return nil
}

func FileSeal(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileSeal); err != nil {
		return err
	}

	if err := c.Files.Seal(ctx, name, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("File sealed: %s", name)
	return nil
}

func FileUnseal(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileUnseal); err != nil {
		return err
	}

	if err := c.Files.Unseal(ctx, name, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("File unsealed: %s", name)
	return nil
}

func FileShred(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	force := cmd.Bool("force")

	if !force && !confirm("Cryptographically destroy "+name+"? This is irreversible.") {
		return nil
	}

	password, err := promptPassword("Enter password to confirm shredding: ")
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileShred); err != nil {
		return err
	}

	privKey, err := c.Identity.GetPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to get private key for signature: %w", err)
	}

	proof, err := c.Files.Shred(ctx, name, c.CurrentIdentityID(), privKey)
	if err != nil {
		return err
	}

	success("File shredded with destruction proof: %s", proof.Signature)
	return nil
}

func FileProtect(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	maxDownloads := int(cmd.Int("max-downloads"))
	geofence := cmd.String("geofence")
	remoteKill := cmd.Bool("remote-kill")
	requireMFA := cmd.Bool("require-mfa")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileSeal); err != nil {
		return err
	}

	// Get file ID first
	fileList, err := c.Files.List(ctx, files.ListOptions{Prefix: name})
	if err != nil {
		return err
	}
	var fileID types.ID
	for _, f := range fileList {
		if f.Name == name {
			fileID = f.ID
			break
		}
	}
	if fileID == "" {
		return fmt.Errorf("file not found: %s", name)
	}

	policy := &files.FileProtectionPolicy{
		FileID:            fileID,
		Name:              fmt.Sprintf("Protection for %s", name),
		MaxDownloadCount:  maxDownloads,
		RemoteKillEnabled: remoteKill,
		RequireMFA:        requireMFA,
		TrackAccess:       true,
		AllowCopy:         true,
		AllowPrint:        true,
		AllowForward:      true,
		AllowEdit:         true,
	}

	if geofence != "" {
		policy.AllowedCountries = strings.Split(geofence, ",")
	}

	if err := c.Files.SetProtectionPolicy(ctx, policy); err != nil {
		return err
	}

	success("Protection policy applied to %s", name)
	return nil
}

func FileKill(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	reason := cmd.String("reason")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileDelete); err != nil {
		return err
	}

	if err := c.Files.KillFile(ctx, name, c.CurrentIdentityID(), reason); err != nil {
		return err
	}

	success("File %s has been remotely killed", name)
	return nil
}

func FileRevive(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeFileSeal); err != nil {
		return err
	}

	if err := c.Files.ReviveFile(ctx, name); err != nil {
		return err
	}

	success("File %s has been revived", name)
	return nil
}

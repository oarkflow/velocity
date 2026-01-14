package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/urfave/cli/v3"
)

// FolderCommands creates the folder command group
func FolderCommands(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("folder", "Folder management operations").
		SetCategory("Storage").
		SetUsage("Manage folders in object storage").
		SetPermission(velocitycli.PermissionUser)

	// Add subcommands
	cmd.AddSubcommand(FolderCreateCommand(db))
	cmd.AddSubcommand(FolderUploadCommand(db))
	cmd.AddSubcommand(FolderListCommand(db))
	cmd.AddSubcommand(FolderInfoCommand(db))
	cmd.AddSubcommand(FolderDeleteCommand(db))
	cmd.AddSubcommand(FolderCopyCommand(db))
	cmd.AddSubcommand(FolderRenameCommand(db))
	cmd.AddSubcommand(FolderSizeCommand(db))
	cmd.AddSubcommand(FolderViewCommand(db))

	return cmd
}

// FolderCreateCommand creates the folder create subcommand
func FolderCreateCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("create", "Create a folder").
		SetUsage("Create folder in storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User identifier",
				Value:   "default",
			},
			&cli.StringSliceFlag{
				Name:    "paths",
				Aliases: []string{"m"},
				Usage:   "Multiple folder paths to create (batch mode)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			path := c.String("path")
			user := c.Root().String("user")
			paths := c.StringSlice("paths")

			// Batch mode
			if len(paths) > 0 {
				allPaths := append([]string{path}, paths...)
				if err := db.CreateFolders(allPaths, user); err != nil {
					return fmt.Errorf("failed to create folders: %w", err)
				}
				fmt.Fprintf(c.Root().Writer, "✓ Created %d folders\n", len(allPaths))
				for _, p := range allPaths {
					fmt.Fprintf(c.Root().Writer, "  - %s\n", p)
				}
				return nil
			}

			// Single folder
			if err := db.CreateFolder(path, user); err != nil {
				return fmt.Errorf("failed to create folder: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Created folder '%s'\n", path)
			return nil
		})
}

// FolderUploadCommand creates the folder upload subcommand
func FolderUploadCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("upload", "Upload a local folder").
		SetUsage("Upload local folder to storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "Local folder path to upload",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "dest",
				Aliases:  []string{"d"},
				Usage:    "Destination folder path in vault",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt objects",
				Value:   true,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "Upload recursively (including subfolders)",
				Value:   true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			sourcePath := c.String("source")
			destPath := c.String("dest")
			user := c.Root().String("user")
			encrypt := c.Bool("encrypt")
			recursive := c.Bool("recursive")

			// Verify source exists
			sourceInfo, err := os.Stat(sourcePath)
			if err != nil {
				return fmt.Errorf("source folder not found: %w", err)
			}
			if !sourceInfo.IsDir() {
				return fmt.Errorf("source is not a folder: %s", sourcePath)
			}

			// Normalize destination path
			if !strings.HasPrefix(destPath, "/") {
				destPath = "/" + destPath
			}

			fmt.Fprintf(c.Root().Writer, "📁 Uploading folder: %s → %s\n", sourcePath, destPath)
			fmt.Fprintf(c.Root().Writer, "   Encryption: %v, Recursive: %v\n\n", encrypt, recursive)

			// Create root folder
			if err := db.CreateFolder(destPath, user); err != nil {
				return fmt.Errorf("failed to create root folder: %w", err)
			}
			fmt.Fprintf(c.Root().Writer, "✓ Created folder: %s\n", destPath)

			stats := &uploadStats{}

			// Walk the directory tree
			err = filepath.Walk(sourcePath, func(localPath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Get relative path
				relPath, err := filepath.Rel(sourcePath, localPath)
				if err != nil {
					return err
				}

				// Skip the root directory itself
				if relPath == "." {
					return nil
				}

				// Convert to vault path
				vaultPath := filepath.Join(destPath, relPath)
				vaultPath = filepath.ToSlash(vaultPath) // Ensure forward slashes

				if info.IsDir() {
					// Create subfolder
					if !recursive && relPath != "." {
						return filepath.SkipDir // Skip subdirectories if not recursive
					}

					if err := db.CreateFolder(vaultPath, user); err != nil {
						fmt.Fprintf(c.Root().Writer, "⚠ Failed to create folder: %s (%v)\n", vaultPath, err)
						stats.failedFolders++
					} else {
						fmt.Fprintf(c.Root().Writer, "✓ Created folder: %s\n", vaultPath)
						stats.folders++
					}
				} else {
					// Upload file
					data, err := os.ReadFile(localPath)
					if err != nil {
						fmt.Fprintf(c.Root().Writer, "⚠ Failed to read file: %s (%v)\n", localPath, err)
						stats.failedFiles++
						return nil
					}

					objOpts := &velocity.ObjectOptions{
						Encrypt: encrypt,
					}

					_, err = db.StoreObject(vaultPath, detectContentType(localPath), user, data, objOpts)
					if err != nil {
						fmt.Fprintf(c.Root().Writer, "⚠ Failed to upload file: %s (%v)\n", vaultPath, err)
						stats.failedFiles++
					} else {
						fmt.Fprintf(c.Root().Writer, "✓ Uploaded file: %s (%d bytes)\n", vaultPath, len(data))
						stats.files++
						stats.totalBytes += int64(len(data))
					}
				}

				return nil
			})

			if err != nil {
				return fmt.Errorf("upload failed: %w", err)
			}

			// Print summary
			fmt.Fprintf(c.Root().Writer, "\n📊 Upload Summary:\n")
			fmt.Fprintf(c.Root().Writer, "   Folders created: %d\n", stats.folders)
			fmt.Fprintf(c.Root().Writer, "   Files uploaded: %d\n", stats.files)
			fmt.Fprintf(c.Root().Writer, "   Total size: %d bytes (%.2f MB)\n", stats.totalBytes, float64(stats.totalBytes)/(1024*1024))
			if stats.failedFolders > 0 || stats.failedFiles > 0 {
				fmt.Fprintf(c.Root().Writer, "   Failed folders: %d\n", stats.failedFolders)
				fmt.Fprintf(c.Root().Writer, "   Failed files: %d\n", stats.failedFiles)
			}
			fmt.Fprintf(c.Root().Writer, "\n✅ Upload complete!\n")

			return nil
		})
}

type uploadStats struct {
	folders       int
	files         int
	totalBytes    int64
	failedFolders int
	failedFiles   int
}

// detectContentType detects content type based on file extension
func detectContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	contentTypes := map[string]string{
		".txt":  "text/plain",
		".md":   "text/markdown",
		".html": "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
		".json": "application/json",
		".xml":  "application/xml",
		".pdf":  "application/pdf",
		".zip":  "application/zip",
		".tar":  "application/x-tar",
		".gz":   "application/gzip",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".svg":  "image/svg+xml",
		".mp3":  "audio/mpeg",
		".mp4":  "video/mp4",
		".go":   "text/plain",
		".py":   "text/plain",
		".sh":   "application/x-sh",
	}

	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

// FolderListCommand creates the folder list subcommand
func FolderListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List folders").
		SetUsage("List folders in storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:    "parent",
				Aliases: []string{"p"},
				Usage:   "Parent folder path (empty for all)",
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "List recursively",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			parent := c.String("parent")
			recursive := c.Bool("recursive")

			folders, err := db.ListFolders(parent, recursive)
			if err != nil {
				return fmt.Errorf("failed to list folders: %w", err)
			}

			if len(folders) == 0 {
				fmt.Fprintf(c.Root().Writer, "No folders found\n")
				return nil
			}

			fmt.Fprintf(c.Root().Writer, "Found %d folders:\n\n", len(folders))
			for _, folder := range folders {
				fmt.Fprintf(c.Root().Writer, "  %s\n", folder.Path)
				fmt.Fprintf(c.Root().Writer, "    Created by: %s\n", folder.CreatedBy)
				fmt.Fprintf(c.Root().Writer, "    Created at: %s\n", folder.CreatedAt.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(c.Root().Writer, "\n")
			}
			return nil
		})
}

// FolderInfoCommand creates the folder info subcommand
func FolderInfoCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("info", "Get folder information").
		SetUsage("Get detailed information about a folder").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Folder path",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			path := c.String("path")

			folder, err := db.GetFolder(path)
			if err != nil {
				return fmt.Errorf("folder not found: %s", path)
			}

			fmt.Fprintf(c.Root().Writer, "Folder Information:\n")
			fmt.Fprintf(c.Root().Writer, "  Path: %s\n", folder.Path)
			fmt.Fprintf(c.Root().Writer, "  Name: %s\n", folder.Name)
			fmt.Fprintf(c.Root().Writer, "  Parent: %s\n", folder.Parent)
			fmt.Fprintf(c.Root().Writer, "  Created by: %s\n", folder.CreatedBy)
			fmt.Fprintf(c.Root().Writer, "  Created at: %s\n", folder.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(c.Root().Writer, "  Modified at: %s\n", folder.ModifiedAt.Format("2006-01-02 15:04:05"))

			if len(folder.Tags) > 0 {
				fmt.Fprintf(c.Root().Writer, "  Tags:\n")
				for k, v := range folder.Tags {
					fmt.Fprintf(c.Root().Writer, "    %s: %s\n", k, v)
				}
			}

			return nil
		})
}

// FolderDeleteCommand creates the folder delete subcommand
func FolderDeleteCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("delete", "Delete a folder").
		SetUsage("Delete folder from storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User identifier",
				Value:   "default",
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "Delete folder and all contents",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			path := c.String("path")
			user := c.Root().String("user")
			recursive := c.Bool("recursive")

			if recursive {
				if err := db.DeleteFolderRecursive(path, user); err != nil {
					return fmt.Errorf("failed to delete folder: %w", err)
				}
				fmt.Fprintf(c.Root().Writer, "✓ Deleted folder '%s' and all contents\n", path)
			} else {
				if err := db.DeleteFolder(path, user); err != nil {
					return fmt.Errorf("failed to delete folder: %w", err)
				}
				fmt.Fprintf(c.Root().Writer, "✓ Deleted empty folder '%s'\n", path)
			}

			return nil
		})
}

// FolderCopyCommand creates the folder copy subcommand
func FolderCopyCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("copy", "Copy a folder").
		SetUsage("Copy folder and all contents").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "Source folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "dest",
				Aliases:  []string{"d"},
				Usage:    "Destination folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User identifier",
				Value:   "default",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			source := c.String("source")
			dest := c.String("dest")
			user := c.Root().String("user")

			if err := db.CopyFolder(source, dest, user); err != nil {
				return fmt.Errorf("failed to copy folder: %w", err)
			}

			size, count, _ := db.GetFolderSize(dest, true)
			fmt.Fprintf(c.Root().Writer, "✓ Copied folder '%s' to '%s'\n", source, dest)
			fmt.Fprintf(c.Root().Writer, "  Contents: %d objects (%d bytes)\n", count, size)
			return nil
		})
}

// FolderRenameCommand creates the folder rename subcommand
func FolderRenameCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("rename", "Rename or move a folder").
		SetUsage("Rename or move folder and all contents").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "old",
				Aliases:  []string{"o"},
				Usage:    "Old folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "new",
				Aliases:  []string{"n"},
				Usage:    "New folder path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User identifier",
				Value:   "default",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			oldPath := c.String("old")
			newPath := c.String("new")
			user := c.Root().String("user")

			if err := db.RenameFolder(oldPath, newPath, user); err != nil {
				return fmt.Errorf("failed to rename folder: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Renamed folder '%s' to '%s'\n", oldPath, newPath)
			return nil
		})
}

// FolderSizeCommand creates the folder size subcommand
func FolderSizeCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("size", "Get folder size").
		SetUsage("Calculate total size of folder contents").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Folder path",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "Calculate recursively",
				Value:   true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			path := c.String("path")
			recursive := c.Bool("recursive")

			size, count, err := db.GetFolderSize(path, recursive)
			if err != nil {
				return fmt.Errorf("failed to get folder size: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "Folder: %s\n", path)
			fmt.Fprintf(c.Root().Writer, "  Objects: %d\n", count)
			fmt.Fprintf(c.Root().Writer, "  Total size: %d bytes (%.2f MB)\n", size, float64(size)/(1024*1024))
			fmt.Fprintf(c.Root().Writer, "  Recursive: %v\n", recursive)
			return nil
		})
}

// FolderViewCommand creates the folder view subcommand to preview folder in browser
func FolderViewCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("view", "View folder in browser").
		SetUsage("View folder contents using previewer").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Folder path in vault",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "compress",
				Aliases: []string{"c"},
				Usage:   "Enable compression for text files",
				Value:   true,
			},
			&cli.Int64Flag{
				Name:  "max-file-size",
				Usage: "Maximum file size in MB",
				Value: 100,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			folderPath := c.String("path")
			compress := c.Bool("compress")
			maxFileSizeMB := c.Int64("max-file-size")
			maxFileSize := maxFileSizeMB * 1024 * 1024
			user := c.Root().String("user")

			fmt.Fprintf(c.Root().Writer, "Loading folder from vault: %s\n", folderPath)

			// Call DB.ViewFolder which handles everything
			if err := db.ViewFolder(folderPath, user, compress, maxFileSize); err != nil {
				return fmt.Errorf("failed to view folder: %w", err)
			}

			return nil
		})
}

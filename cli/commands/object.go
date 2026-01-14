package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/urfave/cli/v3"
)

// ObjectCommands creates the object/file command group
func ObjectCommands(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("object", "Object storage operations").
		SetCategory("Storage").
		SetUsage("Manage object/file storage").
		SetPermission(velocitycli.PermissionUser)

	// Add subcommands
	cmd.AddSubcommand(ObjectPutCommand(db))
	cmd.AddSubcommand(ObjectGetCommand(db))
	cmd.AddSubcommand(ObjectDeleteCommand(db))
	cmd.AddSubcommand(ObjectListCommand(db))
	cmd.AddSubcommand(ObjectInfoCommand(db))
	cmd.AddSubcommand(ObjectViewCommand(db))

	return cmd
}

// ObjectPutCommand creates the object put subcommand
func ObjectPutCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("put", "Upload an object/file").
		SetUsage("Upload file to object storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Object path in storage",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "file",
				Aliases:  []string{"f"},
				Usage:    "Local file path to upload",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "content-type",
				Aliases: []string{"c"},
				Usage:   "Content type (auto-detected if not specified)",
			},
			&cli.BoolFlag{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt the object",
				Value:   true,
			},
			&cli.StringSliceFlag{
				Name:    "tag",
				Aliases: []string{"t"},
				Usage:   "Tags in format key=value (can specify multiple)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			objPath := c.String("path")
			filePath := c.String("file")
			user := c.Root().String("user") // Get from global flag
			contentType := c.String("content-type")
			encrypt := c.Bool("encrypt")
			tags := c.StringSlice("tag")

			// Read file
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			// Auto-detect content type if not specified
			if contentType == "" {
				ext := filepath.Ext(filePath)
				contentType = getContentType(ext)
			}

			// Parse tags
			tagMap := make(map[string]string)
			for _, tag := range tags {
				key, value := parseTag(tag)
				if key != "" {
					tagMap[key] = value
				}
			}

			opts := &velocity.ObjectOptions{
				Encrypt: encrypt,
				Tags:    tagMap,
			}

			meta, err := db.StoreObject(objPath, contentType, user, data, opts)
			if err != nil {
				return fmt.Errorf("failed to store object: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Uploaded object\n")
			fmt.Fprintf(c.Root().Writer, "  Path: %s\n", meta.Path)
			fmt.Fprintf(c.Root().Writer, "  Object ID: %s\n", meta.ObjectID)
			fmt.Fprintf(c.Root().Writer, "  Size: %d bytes\n", meta.Size)
			fmt.Fprintf(c.Root().Writer, "  Encrypted: %v\n", meta.Encrypted)
			fmt.Fprintf(c.Root().Writer, "  Content Type: %s\n", meta.ContentType)
			return nil
		})
}

// ObjectGetCommand creates the object get subcommand
func ObjectGetCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("get", "Download an object/file").
		SetUsage("Download file from object storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Object path in storage",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output file path",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			objPath := c.String("path")
			outputPath := c.String("output")
			user := c.Root().String("user")

			data, meta, err := db.GetObject(objPath, user)
			if err != nil {
				return fmt.Errorf("failed to get object: %w", err)
			}

			// Create output directory if needed
			dir := filepath.Dir(outputPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}

			// Write file
			if err := os.WriteFile(outputPath, data, 0644); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Downloaded object\n")
			fmt.Fprintf(c.Root().Writer, "  Path: %s\n", meta.Path)
			fmt.Fprintf(c.Root().Writer, "  Size: %d bytes\n", meta.Size)
			fmt.Fprintf(c.Root().Writer, "  Output: %s\n", outputPath)
			return nil
		})
}

// ObjectDeleteCommand creates the object delete subcommand
func ObjectDeleteCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("delete", "Delete an object/file").
		SetUsage("Delete file from object storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Object path in storage",
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
			objPath := c.String("path")
			user := c.Root().String("user")

			if err := db.DeleteObject(objPath, user); err != nil {
				return fmt.Errorf("failed to delete object: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Deleted object '%s'\n", objPath)
			return nil
		})
}

// ObjectListCommand creates the object list subcommand
func ObjectListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List objects").
		SetUsage("List objects in storage").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:    "prefix",
				Aliases: []string{"p"},
				Usage:   "Filter by prefix",
			},
			&cli.StringFlag{
				Name:    "folder",
				Aliases: []string{"f"},
				Usage:   "Filter by folder",
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "List recursively",
				Value:   false,
			},
			&cli.IntFlag{
				Name:    "limit",
				Aliases: []string{"l"},
				Usage:   "Maximum number of objects",
				Value:   100,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			prefix := c.String("prefix")
			folder := c.String("folder")
			recursive := c.Bool("recursive")
			limit := c.Int("limit")

			opts := velocity.ObjectListOptions{
				Prefix:    prefix,
				Folder:    folder,
				Recursive: recursive,
				MaxKeys:   limit,
			}

			objects, err := db.ListObjects(opts)
			if err != nil {
				return fmt.Errorf("failed to list objects: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "Found %d objects:\n\n", len(objects))
			for _, obj := range objects {
				fmt.Fprintf(c.Root().Writer, "  %s\n", obj.Path)
				fmt.Fprintf(c.Root().Writer, "    Size: %d bytes\n", obj.Size)
				fmt.Fprintf(c.Root().Writer, "    Type: %s\n", obj.ContentType)
				fmt.Fprintf(c.Root().Writer, "    Encrypted: %v\n", obj.Encrypted)
				fmt.Fprintf(c.Root().Writer, "\n")
			}
			return nil
		})
}

// ObjectInfoCommand creates the object info subcommand
func ObjectInfoCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("info", "Get object metadata").
		SetUsage("Get detailed information about an object").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Object path in storage",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			objPath := c.String("path")

			meta, err := db.GetObjectMetadata(objPath)
			if err != nil {
				return fmt.Errorf("object not found: %s", objPath)
			}

			fmt.Fprintf(c.Root().Writer, "Object Information:\n")
			fmt.Fprintf(c.Root().Writer, "  Path: %s\n", meta.Path)
			fmt.Fprintf(c.Root().Writer, "  Object ID: %s\n", meta.ObjectID)
			fmt.Fprintf(c.Root().Writer, "  Version ID: %s\n", meta.VersionID)
			fmt.Fprintf(c.Root().Writer, "  Size: %d bytes\n", meta.Size)
			fmt.Fprintf(c.Root().Writer, "  Content Type: %s\n", meta.ContentType)
			fmt.Fprintf(c.Root().Writer, "  Encrypted: %v\n", meta.Encrypted)
			fmt.Fprintf(c.Root().Writer, "  Hash: %s\n", meta.Hash)
			fmt.Fprintf(c.Root().Writer, "  Created At: %s\n", meta.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(c.Root().Writer, "  Created By: %s\n", meta.CreatedBy)

			if len(meta.Tags) > 0 {
				fmt.Fprintf(c.Root().Writer, "  Tags:\n")
				for k, v := range meta.Tags {
					fmt.Fprintf(c.Root().Writer, "    %s: %s\n", k, v)
				}
			}

			return nil
		})
}

// ObjectViewCommand creates the object view subcommand
func ObjectViewCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("view", "View object in browser").
		SetUsage("Preview object in browser using viewer").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Object path in storage",
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
			objPath := c.String("path")
			user := c.Root().String("user")

			fmt.Fprintf(c.Root().Writer, "Opening preview for '%s'...\n", objPath)
			if err := db.ViewObject(objPath, user); err != nil {
				return fmt.Errorf("failed to view object: %w", err)
			}

			return nil
		})
}

func getContentType(ext string) string {
	types := map[string]string{
		".txt":  "text/plain",
		".md":   "text/markdown",
		".json": "application/json",
		".xml":  "application/xml",
		".pdf":  "application/pdf",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".svg":  "image/svg+xml",
		".html": "text/html",
		".css":  "text/css",
		".js":   "text/javascript",
		".go":   "text/x-go",
		".py":   "text/x-python",
	}

	if ct, ok := types[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

func parseTag(tag string) (string, string) {
	for i, c := range tag {
		if c == '=' {
			return tag[:i], tag[i+1:]
		}
	}
	return tag, ""
}

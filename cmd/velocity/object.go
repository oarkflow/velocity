package main

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"
)

func objectCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "object",
		Usage: "Object storage operations",
		Commands: []*cli.Command{
			{
				Name:      "put",
				Usage:     "Store an object",
				ArgsUsage: "<key>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return fmt.Errorf("usage: velocity object put <key>")
					}
					key := cmd.Args().Get(0)
					_, err := db.StoreObject(key, "application/octet-stream", "system", []byte(key), nil)
					if err != nil {
						return fmt.Errorf("failed to store: %w", err)
					}
					fmt.Printf("Stored: %s\n", key)
					return nil
				},
			},
			{
				Name:      "get",
				Usage:     "Retrieve an object",
				ArgsUsage: "<key>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return fmt.Errorf("usage: velocity object get <key>")
					}
					key := cmd.Args().Get(0)
					data, _, err := db.GetObject(key, "system")
					if err != nil {
						return fmt.Errorf("failed to get: %w", err)
					}
					fmt.Println(string(data))
					return nil
				},
			},
			{
				Name:      "preview",
				Usage:     "Store a file and open browser preview",
				ArgsUsage: "<file> [object-path]",
				Aliases:   []string{"render"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "content-type", Usage: "MIME content type"},
					&cli.StringFlag{Name: "user", Usage: "User identity", Value: "system"},
					&cli.StringFlag{Name: "path", Usage: "Object storage path"},
					&cli.BoolFlag{Name: "public", Usage: "Make object publicly accessible"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 {
						return fmt.Errorf("usage: velocity object preview <file> [object-path] [--content-type TYPE] [--user USER] [--public]")
					}
					filePath := cmd.Args().Get(0)
					objectPath := ""
					if cmd.Args().Len() >= 2 {
						objectPath = cmd.Args().Get(1)
					} else if flagPath := cmd.String("path"); flagPath != "" {
						objectPath = flagPath
					} else {
						objectPath = filepath.ToSlash(filepath.Base(filePath))
					}
					user := cmd.String("user")
					contentType := cmd.String("content-type")
					if contentType == "" {
						var err error
						contentType, err = detectFileContentType(filePath)
						if err != nil {
							return err
						}
					}
					data, err := os.ReadFile(filePath)
					if err != nil {
						return fmt.Errorf("failed to read file: %w", err)
					}
					opts := &velocity.ObjectOptions{}
					if cmd.Bool("public") {
						opts.ACL = &velocity.ObjectACL{Owner: user, Public: true}
					}
					meta, err := db.StoreObject(objectPath, contentType, user, data, opts)
					if err != nil {
						return fmt.Errorf("failed to store object: %w", err)
					}
					fmt.Printf("Stored object: %s (%d bytes, %s)\n", meta.Path, meta.Size, meta.ContentType)
					fmt.Printf("Opening Preview in browser: %s\n", meta.Path)
					if err := db.ViewObject(meta.Path, user); err != nil {
						return fmt.Errorf("failed to preview object: %w", err)
					}
					return nil
				},
			},
		},
	}
}

func detectFileContentType(path string) (string, error) {
	if ext := filepath.Ext(path); ext != "" {
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			return contentType, nil
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file for content detection: %w", err)
	}
	defer file.Close()
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("failed to read file for content detection: %w", err)
	}
	return http.DetectContentType(buf[:n]), nil
}

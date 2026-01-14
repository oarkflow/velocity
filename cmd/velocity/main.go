package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/oarkflow/velocity/cli/commands"
	"github.com/urfave/cli/v3"
)

// Resolve DB path: flag > env > default
func getDBPath() string {
	if path := os.Getenv("VELOCITY_DB_PATH"); path != "" {
		return path
	}
	return "./velocitydb"
}

func main() {
	// Create command registry
	registry := velocitycli.NewRegistry()

	// --- Permission Checker ---
	permChecker := velocitycli.NewDefaultPermissionChecker()
	permChecker.SetUserRole("owner", velocitycli.PermissionOwner)
	permChecker.SetUserRole("admin", velocitycli.PermissionAdmin)
	permChecker.SetUserRole("user1", velocitycli.PermissionUser)
	permChecker.SetUserRole("default", velocitycli.PermissionUser) // Default user has User permissions
	registry.SetPermissionChecker(permChecker)

	// --- Flag Validator ---
	flagValidator := velocitycli.NewDefaultFlagValidator()

	flagValidator.AddValidator("ttl", func(v interface{}) error {
		ttl, ok := v.(int)
		if !ok {
			return fmt.Errorf("ttl must be an integer")
		}
		if ttl < 0 {
			return fmt.Errorf("ttl cannot be negative")
		}
		return nil
	})

	flagValidator.SetFlagPermission("encrypt", velocitycli.PermissionUser)
	flagValidator.SetFlagPermission("recursive", velocitycli.PermissionUser)
	registry.SetFlagValidator(flagValidator)

	// --- Initialize DB ---
	db, err := velocity.NewWithConfig(velocity.Config{
		Path: getDBPath(),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
		},
		MaxUploadSize: 100 * 1024 * 1024,
	})
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// --- Register Commands ---
	if err := registry.Register(commands.DataCommands(db)); err != nil {
		log.Fatalf("Failed to register data commands: %v", err)
	}
	if err := registry.Register(commands.ObjectCommands(db)); err != nil {
		log.Fatalf("Failed to register object commands: %v", err)
	}
	if err := registry.Register(commands.FolderCommands(db)); err != nil {
		log.Fatalf("Failed to register folder commands: %v", err)
	}
	if err := registry.Register(commands.SecretCommands(db)); err != nil {
		log.Fatalf("Failed to register secret commands: %v", err)
	}
	if err := registry.Register(commands.BackupCommand(db)); err != nil {
		log.Fatalf("Failed to register backup commands: %v", err)
	}
	if err := registry.Register(commands.ExportCommand(db)); err != nil {
		log.Fatalf("Failed to register export command: %v", err)
	}
	if err := registry.Register(commands.ImportCommand(db)); err != nil {
		log.Fatalf("Failed to register import command: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get user home directory: %v", err)
	}

	// --- CLI App ---
	app := &cli.Command{
		Name:    "velocity",
		Usage:   "Velocity DB command-line interface",
		Version: "1.0.0",

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User identifier for operations",
				Value:   "default",
			},
			&cli.StringFlag{
				Name:    "db-path",
				Aliases: []string{"d"},
				Usage:   "Database path",
				Value:   filepath.Join(home, ".velocity"),
			},
		},

		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			// You can add global setup here if needed
			return ctx, nil
		},

		Commands: registry.GetCommands(),
	}

	// Run CLI
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

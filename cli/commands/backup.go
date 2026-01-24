package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/urfave/cli/v3"
)

// BackupCommand creates the backup parent command
func BackupCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("backup", "Database backup and restore operations").
		SetUsage("Backup and restore database contents").
		SetPermission(velocitycli.PermissionAdmin).
		AddSubcommand(BackupCreateCommand(db)).
		AddSubcommand(BackupRestoreCommand(db)).
		AddSubcommand(BackupListCommand(db)).
		AddSubcommand(BackupVerifyCommand(db)).
		AddSubcommand(BackupAuditCommand(db))
}

// BackupCreateCommand creates a database backup
func BackupCreateCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("create", "Create a database backup").
		SetUsage("Create a backup of secrets, folders, and objects").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output backup file path",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "compress",
				Aliases: []string{"z"},
				Usage:   "Compress the backup with gzip",
				Value:   true,
			},
			&cli.BoolFlag{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt the backup",
				Value:   true,
			},
			&cli.StringSliceFlag{
				Name:    "include",
				Aliases: []string{"i"},
				Usage:   "Item types to include: secrets, folders, objects (default: all)",
			},
			&cli.StringFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Usage:   "Path prefix filter (only backup items matching prefix)",
			},
			&cli.StringFlag{
				Name:    "description",
				Aliases: []string{"d"},
				Usage:   "Backup description",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			output := c.String("output")
			compress := c.Bool("compress")
			encrypt := c.Bool("encrypt")
			includes := c.StringSlice("include")
			filter := c.String("filter")
			description := c.String("description")
			user := c.Root().String("user")

			if len(includes) == 0 {
				includes = []string{"secrets", "folders", "objects"}
			}

			fmt.Printf("Creating backup: %s\n", output)
			fmt.Printf("  Compress: %v\n", compress)
			fmt.Printf("  Encrypt: %v\n", encrypt)
			fmt.Printf("  Include: %v\n", includes)
			if filter != "" {
				fmt.Printf("  Filter: %s\n", filter)
			}

			startTime := time.Now()

			opts := velocity.BackupOptions{
				OutputPath:   output,
				Compress:     compress,
				Encrypt:      encrypt,
				IncludeTypes: includes,
				Filter:       filter,
				User:         user,
				Description:  description,
			}

			if err := db.Backup(opts); err != nil {
				return fmt.Errorf("backup failed: %w", err)
			}

			duration := time.Since(startTime)
			fmt.Printf("✓ Backup created successfully in %s\n", duration.Round(time.Millisecond))

			return nil
		})
}

// BackupRestoreCommand restores from a backup
func BackupRestoreCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("restore", "Restore from a backup").
		SetUsage("Restore database from a backup file").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "input",
				Aliases:  []string{"i"},
				Usage:    "Input backup file path",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "overwrite",
				Aliases: []string{"w"},
				Usage:   "Overwrite existing items",
				Value:   false,
			},
			&cli.StringSliceFlag{
				Name:    "include",
				Aliases: []string{"t"},
				Usage:   "Item types to restore: secrets, folders, objects (default: all)",
			},
			&cli.StringFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Usage:   "Path prefix filter (only restore items matching prefix)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			input := c.String("input")
			overwrite := c.Bool("overwrite")
			includes := c.StringSlice("include")
			filter := c.String("filter")
			user := c.Root().String("user")

			fmt.Printf("Restoring from backup: %s\n", input)
			fmt.Printf("  Overwrite: %v\n", overwrite)
			if len(includes) > 0 {
				fmt.Printf("  Include: %v\n", includes)
			}
			if filter != "" {
				fmt.Printf("  Filter: %s\n", filter)
			}

			startTime := time.Now()

			opts := velocity.RestoreOptions{
				BackupPath:   input,
				Overwrite:    overwrite,
				Filter:       filter,
				User:         user,
				IncludeTypes: includes,
			}

			if err := db.Restore(opts); err != nil {
				return fmt.Errorf("restore failed: %w", err)
			}

			duration := time.Since(startTime)
			fmt.Printf("✓ Restore completed in %s\n", duration.Round(time.Millisecond))

			return nil
		})
}

// BackupListCommand lists available backups
func BackupListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List backup files").
		SetUsage("List available backup files in a directory").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:    "directory",
				Aliases: []string{"d"},
				Usage:   "Directory containing backups",
				Value:   "./backups",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			directory := c.String("directory")

			matches, err := filepath.Glob(filepath.Join(directory, "*.backup"))
			if err != nil {
				return fmt.Errorf("failed to list backups: %w", err)
			}

			if len(matches) == 0 {
				fmt.Println("No backup files found")
				return nil
			}

			fmt.Printf("Found %d backup file(s):\n", len(matches))
			for _, match := range matches {
				fmt.Printf("  - %s\n", match)
			}

			return nil
		})
}

// ExportCommand creates the export parent command
func ExportCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("export", "Export data to files").
		SetUsage("Export secrets, folders, and objects to various formats").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output file path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "Export format: json, encrypted-json, tar, tar.gz",
				Value:   "json",
			},
			&cli.StringFlag{
				Name:     "type",
				Aliases:  []string{"t"},
				Usage:    "Item type: secret, folder, object",
				Required: true,
			},
			&cli.StringSliceFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Item path(s) to export",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "For folders: recursively export all contents",
				Value:   true,
			},
			&cli.BoolFlag{
				Name:    "pretty",
				Aliases: []string{"P"},
				Usage:   "Pretty print JSON output",
				Value:   true,
			},
			&cli.BoolFlag{
				Name:    "compress",
				Aliases: []string{"z"},
				Usage:   "Compress output",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			output := c.String("output")
			format := c.String("format")
			itemType := c.String("type")
			paths := c.StringSlice("path")
			recursive := c.Bool("recursive")
			pretty := c.Bool("pretty")
			compress := c.Bool("compress")
			user := c.Root().String("user")

			fmt.Printf("Exporting %s(s) to: %s\n", itemType, output)
			fmt.Printf("  Format: %s\n", format)
			fmt.Printf("  Paths: %v\n", paths)

			opts := velocity.ExportOptions{
				Format:     format,
				OutputPath: output,
				Pretty:     pretty,
				Compress:   compress,
				User:       user,
				ItemType:   itemType,
				Paths:      paths,
				Recursive:  recursive,
			}

			if err := db.Export(opts); err != nil {
				return fmt.Errorf("export failed: %w", err)
			}

			fmt.Printf("✓ Export completed successfully\n")
			return nil
		})
}

// ImportCommand creates the import command
func ImportCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("import", "Import data from files").
		SetUsage("Import secrets, folders, and objects from various formats").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "input",
				Aliases:  []string{"i"},
				Usage:    "Input file path",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "Import format: json, encrypted-json, tar, tar.gz, auto (default: auto)",
				Value:   "auto",
			},
			&cli.BoolFlag{
				Name:    "overwrite",
				Aliases: []string{"w"},
				Usage:   "Overwrite existing items",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "dry-run",
				Aliases: []string{"n"},
				Usage:   "Show what would be imported without actually importing",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			input := c.String("input")
			format := c.String("format")
			overwrite := c.Bool("overwrite")
			dryRun := c.Bool("dry-run")
			user := c.Root().String("user")

			fmt.Printf("Importing from: %s\n", input)
			fmt.Printf("  Format: %s\n", format)
			fmt.Printf("  Overwrite: %v\n", overwrite)
			if dryRun {
				fmt.Printf("  Mode: DRY RUN (no changes will be made)\n")
			}

			opts := velocity.ImportOptions{
				Format:    format,
				InputPath: input,
				Overwrite: overwrite,
				User:      user,
				DryRun:    dryRun,
			}

			if err := db.Import(opts); err != nil {
				return fmt.Errorf("import failed: %w", err)
			}

			if !dryRun {
				fmt.Printf("✓ Import completed successfully\n")
			}
			return nil
		})
}

// BackupVerifyCommand verifies backup integrity
func BackupVerifyCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("verify", "Verify backup integrity").
		SetUsage("Verify cryptographic signature and integrity of backup file").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "input",
				Aliases:  []string{"i"},
				Usage:    "Backup file to verify",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			input := c.String("input")

			fmt.Printf("🔐 Verifying backup integrity: %s\n\n", input)

			metadata, err := db.VerifyBackupIntegrity(input)
			if err != nil {
				fmt.Printf("❌ Verification FAILED: %v\n", err)
				return err
			}

			fmt.Printf("✅ Backup integrity verified successfully!\n\n")
			fmt.Printf("Backup Information:\n")
			fmt.Printf("  Version: %s\n", metadata.Version)
			fmt.Printf("  Created: %s\n", metadata.CreatedAt.Format(time.RFC3339))
			fmt.Printf("  Items: %d\n", metadata.ItemCount)
			fmt.Printf("  Size: %d bytes\n", metadata.TotalSize)
			fmt.Printf("  User: %s\n", metadata.User)
			if metadata.Description != "" {
				fmt.Printf("  Description: %s\n", metadata.Description)
			}

			fmt.Printf("\nSignature Details:\n")
			fmt.Printf("  Algorithm: %s\n", metadata.Signature.Algorithm)
			fmt.Printf("  Signed by: %s\n", metadata.Signature.SignedBy)
			fmt.Printf("  Signed at: %s\n", metadata.Signature.SignedAt.Format(time.RFC3339))
			fmt.Printf("  Hash: %s...\n", metadata.Signature.Hash[:32])

			if metadata.Signature.Fingerprint != "" {
				fmt.Printf("  Device: %s...\n", metadata.Signature.Fingerprint[:16])
			}

			if metadata.Signature.ChainID != "" {
				fmt.Printf("  Chain ID: %s\n", metadata.Signature.ChainID)
			}

			if len(metadata.ChainLinks) > 0 {
				fmt.Printf("\nChain Links: %d previous backup(s)\n", len(metadata.ChainLinks))
				for i, link := range metadata.ChainLinks {
					fmt.Printf("  %d. %s\n", i+1, link)
				}
			}

			if metadata.AuditID != "" {
				fmt.Printf("\nAudit ID: %s\n", metadata.AuditID)
			}

			return nil
		})
}

// BackupAuditCommand shows audit trail
func BackupAuditCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("audit", "View audit trail").
		SetUsage("View backup/restore audit trail with chain verification").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:    "operation",
				Aliases: []string{"op"},
				Usage:   "Filter by operation: backup, restore, export, import",
			},
			&cli.StringFlag{
				Name:    "start",
				Aliases: []string{"s"},
				Usage:   "Start date (YYYY-MM-DD)",
			},
			&cli.StringFlag{
				Name:    "end",
				Aliases: []string{"e"},
				Usage:   "End date (YYYY-MM-DD)",
			},
			&cli.BoolFlag{
				Name:    "verify-chain",
				Aliases: []string{"v"},
				Usage:   "Verify audit chain integrity",
				Value:   false,
			},
			&cli.StringFlag{
				Name:    "export",
				Aliases: []string{"x"},
				Usage:   "Export audit trail to file",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			operation := c.String("operation")
			startStr := c.String("start")
			endStr := c.String("end")
			verifyChain := c.Bool("verify-chain")
			exportPath := c.String("export")

			var startDate, endDate time.Time
			var err error

			if startStr != "" {
				startDate, err = time.Parse("2006-01-02", startStr)
				if err != nil {
					return fmt.Errorf("invalid start date: %w", err)
				}
			}

			if endStr != "" {
				endDate, err = time.Parse("2006-01-02", endStr)
				if err != nil {
					return fmt.Errorf("invalid end date: %w", err)
				}
			}

			// Export audit trail if requested
			if exportPath != "" {
				fmt.Printf("Exporting audit trail to: %s\n", exportPath)
				if err := db.ExportAuditTrail(exportPath, startDate, endDate); err != nil {
					return fmt.Errorf("failed to export audit trail: %w", err)
				}
				fmt.Printf("✓ Audit trail exported successfully\n")
				return nil
			}

			// Verify chain if requested
			if verifyChain {
				fmt.Println("🔐 Verifying audit chain integrity...")
				valid, issues, err := db.VerifyAuditChain()
				if err != nil {
					return fmt.Errorf("failed to verify audit chain: %w", err)
				}

				if valid {
					fmt.Println("✅ Audit chain integrity verified - no issues found")
				} else {
					fmt.Printf("❌ Audit chain has %d issue(s):\n", len(issues))
					for _, issue := range issues {
						fmt.Printf("  - %s\n", issue)
					}
					fmt.Println()
				}
			}

			// Retrieve audit records
			records, err := db.GetAuditTrail(startDate, endDate, operation)
			if err != nil {
				return fmt.Errorf("failed to retrieve audit trail: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No audit records found")
				return nil
			}

			fmt.Printf("📋 Audit Trail (%d records)\n\n", len(records))

			for i, record := range records {
				fmt.Printf("%d. [%s] %s by %s\n",
					i+1,
					record.Timestamp.Format("2006-01-02 15:04:05"),
					record.Operation,
					record.User)

				fmt.Printf("   File: %s\n", record.FilePath)
				fmt.Printf("   Items: %d | Success: %v\n", record.ItemCount, record.Success)

				if record.ErrorMsg != "" {
					fmt.Printf("   Error: %s\n", record.ErrorMsg)
				}

				if record.Signature.SignedBy != "" {
					fmt.Printf("   Signature: %s... (by %s)\n",
						record.Signature.HMAC[:16],
						record.Signature.SignedBy)
				}

				if record.PreviousID != "" {
					fmt.Printf("   Chain: → %s\n", record.PreviousID[:16])
				}

				fmt.Println()
			}

			return nil
		})
}

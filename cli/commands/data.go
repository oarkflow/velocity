package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/urfave/cli/v3"
)

// -----------------------------
// PUT COMMAND
// -----------------------------

func DataPutCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("put", "Store a key-value pair").
		SetUsage("Store data in the database").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Key name",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "value",
				Aliases:  []string{"v"},
				Usage:    "Value to store",
				Required: true,
			},
			&cli.IntFlag{
				Name:    "ttl",
				Aliases: []string{"t"},
				Usage:   "Time to live in seconds (0 = no expiration)",
				Value:   0,
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Parse value as JSON",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			key := c.String("key")
			value := c.String("value")
			ttl := c.Int("ttl")
			isJSON := c.Bool("json")

			var data []byte
			if isJSON {
				if !json.Valid([]byte(value)) {
					return fmt.Errorf("invalid JSON value")
				}
				data = []byte(value)
			} else {
				data = []byte(value)
			}

			if err := db.PutWithTTL([]byte(key), data, time.Duration(ttl)); err != nil {
				return fmt.Errorf("failed to store data: %w", err)
			}

			if ttl > 0 {
				fmt.Fprintf(c.Root().Writer, "✓ Stored key '%s' (size: %d bytes, TTL: %d seconds)\n", key, len(data), ttl)
			} else {
				fmt.Fprintf(c.Root().Writer, "✓ Stored key '%s' (size: %d bytes)\n", key, len(data))
			}
			return nil
		})
}

// -----------------------------
// GET COMMAND
// -----------------------------

func DataGetCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("get", "Retrieve a value by key").
		SetUsage("Get data from the database").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Key name",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Format output as JSON",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			key := c.String("key")
			isJSON := c.Bool("json")

			value, err := db.Get([]byte(key))
			if err != nil {
				return fmt.Errorf("key not found: %s", key)
			}

			if isJSON {
				fmt.Fprintf(c.Root().Writer, "Key: %s\nValue: %s\nSize: %d bytes\n", key, string(value), len(value))
			} else {
				fmt.Fprintf(c.Root().Writer, "%s\n", string(value))
			}

			return nil
		})
}

// -----------------------------
// DELETE COMMAND
// -----------------------------

func DataDeleteCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("delete", "Delete a key-value pair").
		SetUsage("Delete data from the database").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Key name",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			key := c.String("key")

			if err := db.Delete([]byte(key)); err != nil {
				return fmt.Errorf("failed to delete key: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Deleted key '%s'\n", key)
			return nil
		})
}

// -----------------------------
// LIST COMMAND
// -----------------------------

func DataListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List all keys").
		SetUsage("List keys in the database").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.IntFlag{
				Name:    "offset",
				Aliases: []string{"o"},
				Usage:   "Offset for pagination",
				Value:   0,
			},
			&cli.IntFlag{
				Name:    "limit",
				Aliases: []string{"l"},
				Usage:   "Limit number of keys",
				Value:   100,
			},
			&cli.StringFlag{
				Name:    "prefix",
				Aliases: []string{"p"},
				Usage:   "Filter keys by prefix",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			offset := c.Int("offset")
			limit := c.Int("limit")
			prefix := c.String("prefix")

			keys, _ := db.KeysPage(offset, limit)

			var filtered [][]byte

			if prefix != "" {
				for _, k := range keys {
					if len(k) >= len(prefix) && string(k[:len(prefix)]) == prefix {
						filtered = append(filtered, k)
					}
				}
			} else {
				filtered = keys
			}

			fmt.Fprintf(c.Root().Writer, "Found %d keys:\n", len(filtered))
			for i, k := range filtered {
				fmt.Fprintf(c.Root().Writer, "%d. %s\n", i+1, string(k))
			}

			return nil
		})
}

// -----------------------------
// EXISTS COMMAND
// -----------------------------

func DataExistsCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("exists", "Check if a key exists").
		SetUsage("Check if key exists in the database").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Key name",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			key := c.String("key")
			exists := db.Has([]byte(key))

			if exists {
				fmt.Fprintf(c.Root().Writer, "✓ Key '%s' exists\n", key)
				os.Exit(0)
			} else {
				fmt.Fprintf(c.Root().Writer, "✗ Key '%s' does not exist\n", key)
				os.Exit(1)
			}

			return nil
		})
}

// -----------------------------
// ROOT DATA COMMAND
// -----------------------------

func DataCommands(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("data", "Data storage operations").
		SetUsage("Manage key-value data storage").
		SetCategory("Storage").
		SetPermission(velocitycli.PermissionUser)

	cmd.AddSubcommand(DataPutCommand(db))
	cmd.AddSubcommand(DataGetCommand(db))
	cmd.AddSubcommand(DataDeleteCommand(db))
	cmd.AddSubcommand(DataListCommand(db))
	cmd.AddSubcommand(DataExistsCommand(db))

	return cmd
}

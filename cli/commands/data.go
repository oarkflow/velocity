package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
// INDEXED PUT COMMAND
// -----------------------------

func DataIndexedPutCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("index", "Store data with search indexing").
		SetUsage("Store data and build search indexes").
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
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Parse value as JSON",
				Value:   false,
			},
			&cli.StringFlag{
				Name:  "schema",
				Usage: "JSON schema for indexing (SearchSchema)",
			},
			&cli.StringFlag{
				Name:  "prefix",
				Usage: "Prefix namespace for schema (e.g. users)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			key := c.String("key")
			value := c.String("value")
			isJSON := c.Bool("json")
			schemaRaw := c.String("schema")
			prefix := c.String("prefix")

			var data []byte
			if isJSON {
				if !json.Valid([]byte(value)) {
					return fmt.Errorf("invalid JSON value")
				}
				data = []byte(value)
			} else {
				data = []byte(value)
			}

			var schema *velocity.SearchSchema
			if strings.TrimSpace(schemaRaw) != "" {
				var parsed velocity.SearchSchema
				if err := json.Unmarshal([]byte(schemaRaw), &parsed); err != nil {
					return fmt.Errorf("invalid schema JSON: %w", err)
				}
				schema = &parsed
			}

			if schema != nil {
				if strings.TrimSpace(prefix) != "" {
					db.SetSearchSchemaForPrefix(prefix, schema)
				} else {
					db.SetSearchSchema(schema)
				}
				db.EnableSearchIndex(true)
			}
			if err := db.Put([]byte(key), data); err != nil {
				return fmt.Errorf("failed to store indexed data: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Indexed key '%s' (size: %d bytes)\n", key, len(data))
			return nil
		})
}

// -----------------------------
// SEARCH COMMAND
// -----------------------------

func DataSearchCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("search", "Search indexed data").
		SetUsage("Search values using full-text and filters").
		SetPermission(velocitycli.PermissionUser).
		AddFlags(
			&cli.StringFlag{
				Name:  "text",
				Usage: "Full-text search query",
			},
			&cli.StringFlag{
				Name:  "prefix",
				Usage: "Key prefix namespace to search within",
			},
			&cli.StringSliceFlag{
				Name:  "filter",
				Usage: "Filter expression (field==value, field>=value, etc). Repeatable.",
			},
			&cli.StringSliceFlag{
				Name:  "hash-field",
				Usage: "Field names to use hash equality index (repeatable)",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "Maximum results",
				Value: 100,
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results as JSON",
				Value: false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			text := c.String("text")
			filters := c.StringSlice("filter")
			hashFields := map[string]bool{}
			for _, f := range c.StringSlice("hash-field") {
				hashFields[f] = true
			}
			limit := c.Int("limit")
			asJSON := c.Bool("json")

			query := velocity.SearchQuery{Prefix: c.String("prefix"), FullText: text, Limit: limit}
			for _, raw := range filters {
				field, op, val, err := parseFilterExpr(raw)
				if err != nil {
					return err
				}
				query.Filters = append(query.Filters, velocity.SearchFilter{
					Field:    field,
					Op:       op,
					Value:    val,
					HashOnly: hashFields[field],
				})
			}

			results, err := db.Search(query)
			if err != nil {
				return err
			}

			if asJSON {
				out := make([]map[string]string, 0, len(results))
				for _, r := range results {
					out = append(out, map[string]string{
						"key":   string(r.Key),
						"value": string(r.Value),
					})
				}
				encoded, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintf(c.Root().Writer, "%s\n", string(encoded))
				return nil
			}

			fmt.Fprintf(c.Root().Writer, "Found %d results:\n", len(results))
			for i, r := range results {
				fmt.Fprintf(c.Root().Writer, "%d. %s => %s\n", i+1, string(r.Key), string(r.Value))
			}
			return nil
		})
}

func parseFilterExpr(raw string) (string, string, any, error) {
	ops := []string{"!=", ">=", "<=", "==", "=", ">", "<"}
	for _, op := range ops {
		if idx := strings.Index(raw, op); idx > 0 {
			field := strings.TrimSpace(raw[:idx])
			valRaw := strings.TrimSpace(raw[idx+len(op):])
			if field == "" || valRaw == "" {
				return "", "", nil, fmt.Errorf("invalid filter: %s", raw)
			}
			return field, op, parseFilterValue(valRaw), nil
		}
	}
	return "", "", nil, fmt.Errorf("invalid filter: %s", raw)
}

func parseFilterValue(raw string) any {
	var v any
	if json.Unmarshal([]byte(raw), &v) == nil {
		return v
	}
	return raw
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
	cmd.AddSubcommand(DataIndexedPutCommand(db))
	cmd.AddSubcommand(DataSearchCommand(db))

	return cmd
}

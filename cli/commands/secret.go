package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/urfave/cli/v3"
)

// SecretCommands creates the secret command group
func SecretCommands(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("secret", "Secret management operations").
		SetCategory("Security").
		SetUsage("Manage encrypted secrets").
		SetPermission(velocitycli.PermissionAdmin)

	// Add subcommands
	cmd.AddSubcommand(SecretSetCommand(db))
	cmd.AddSubcommand(SecretGetCommand(db))
	cmd.AddSubcommand(SecretDeleteCommand(db))
	cmd.AddSubcommand(SecretListCommand(db))
	cmd.AddSubcommand(SecretRotateCommand(db))

	return cmd
}

// SecretSetCommand creates the secret set subcommand
func SecretSetCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("set", "Store a secret").
		SetUsage("Store encrypted secret value").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "Secret name",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "value",
				Aliases:  []string{"v"},
				Usage:    "Secret value",
				Required: true,
			},
			&cli.IntFlag{
				Name:    "ttl",
				Aliases: []string{"t"},
				Usage:   "Time to live in seconds (0 = no expiration)",
				Value:   0,
			},
			&cli.StringFlag{
				Name:    "category",
				Aliases: []string{"c"},
				Usage:   "Secret category",
				Value:   "general",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			name := c.String("name")
			value := c.String("value")
			ttl := c.Int("ttl")
			category := c.String("category")

			// Split the name by dot notation
			parts := splitDotNotation(name)
			rootKey := parts[0]

			// Construct the storage key using root name
			key := fmt.Sprintf("secret:%s:%s", category, rootKey)

			// If there's dot notation (nested key)
			if len(parts) > 1 {
				// Get existing secret data
				existingData, err := db.Get([]byte(key))
				var dataMap map[string]interface{}

				if err != nil {
					// Secret doesn't exist, create new
					dataMap = make(map[string]interface{})
				} else {
					// Parse existing data as JSON
					if err := json.Unmarshal(existingData, &dataMap); err != nil {
						// Existing data is not JSON, create new structure
						dataMap = make(map[string]interface{})
					}
				}

				// Parse the value (could be JSON or plain string)
				parsedValue := parseJSONValue(value)

				// Set the nested value using only the nested path (skip root key)
				nestedPath := parts[1:]
				setNestedValue(dataMap, nestedPath, parsedValue)

				// Marshal back to JSON
				jsonData, err := json.MarshalIndent(dataMap, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}

				if err := db.PutWithTTL([]byte(key), jsonData, time.Duration(ttl)); err != nil {
					return fmt.Errorf("failed to store secret: %w", err)
				}

				fmt.Fprintf(c.Root().Writer, "✓ Updated secret '%s'\n", name)
				fmt.Fprintf(c.Root().Writer, "  Category: %s\n", category)
				fmt.Fprintf(c.Root().Writer, "  Root key: %s\n", rootKey)
				if ttl > 0 {
					fmt.Fprintf(c.Root().Writer, "  TTL: %d seconds\n", ttl)
				}
			} else {
				// No dot notation, store as-is (might be JSON or plain string)
				parsedValue := parseJSONValue(value)

				var finalData []byte
				if jsonObj, ok := parsedValue.(map[string]interface{}); ok {
					// It's a JSON object, store it prettified
					jsonData, err := json.MarshalIndent(jsonObj, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %w", err)
					}
					finalData = jsonData
				} else if jsonArr, ok := parsedValue.([]interface{}); ok {
					// It's a JSON array, store it prettified
					jsonData, err := json.MarshalIndent(jsonArr, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %w", err)
					}
					finalData = jsonData
				} else {
					// Plain string or primitive value
					finalData = []byte(value)
				}

				if err := db.PutWithTTL([]byte(key), finalData, time.Duration(ttl)); err != nil {
					return fmt.Errorf("failed to store secret: %w", err)
				}

				fmt.Fprintf(c.Root().Writer, "✓ Stored secret '%s'\n", name)
				fmt.Fprintf(c.Root().Writer, "  Category: %s\n", category)
				if ttl > 0 {
					fmt.Fprintf(c.Root().Writer, "  TTL: %d seconds\n", ttl)
				}
			}

			return nil
		})
}

// SecretGetCommand creates the secret get subcommand
func SecretGetCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("get", "Retrieve a secret").
		SetUsage("Get encrypted secret value").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "Secret name",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "category",
				Aliases: []string{"c"},
				Usage:   "Secret category",
				Value:   "general",
			},
			&cli.BoolFlag{
				Name:    "show",
				Aliases: []string{"s"},
				Usage:   "Show secret value (otherwise shows masked)",
				Value:   false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			name := c.String("name")
			category := c.String("category")
			show := c.Bool("show")

			// Split the name by dot notation
			parts := splitDotNotation(name)
			rootKey := parts[0]

			key := fmt.Sprintf("secret:%s:%s", category, rootKey)

			value, err := db.Get([]byte(key))
			if err != nil {
				return fmt.Errorf("secret not found: %s", name)
			}

			fmt.Fprintf(c.Root().Writer, "Secret: %s\n", name)
			fmt.Fprintf(c.Root().Writer, "Category: %s\n", category)

			// If there's dot notation (nested key)
			if len(parts) > 1 {
				// Parse as JSON
				var dataMap map[string]interface{}
				if err := json.Unmarshal(value, &dataMap); err != nil {
					return fmt.Errorf("failed to parse secret as JSON: %w", err)
				}

				// Get nested value using only the nested path (skip root key)
				nestedPath := parts[1:]
				nestedValue, exists := getNestedValue(dataMap, nestedPath)
				if !exists {
					return fmt.Errorf("nested key not found: %s", name)
				}

				// Convert to string for display
				var displayValue string
				switch v := nestedValue.(type) {
				case string:
					displayValue = v
				case map[string]interface{}, []interface{}:
					jsonBytes, _ := json.MarshalIndent(v, "", "  ")
					displayValue = string(jsonBytes)
				default:
					jsonBytes, _ := json.Marshal(v)
					displayValue = string(jsonBytes)
				}

				if show {
					fmt.Fprintf(c.Root().Writer, "Value: %s\n", displayValue)
				} else {
					fmt.Fprintf(c.Root().Writer, "Value: %s (use --show to display)\n", maskSecret(displayValue))
				}
			} else {
				// Return full value (might be JSON or plain string)
				// Try to pretty-print if it's JSON
				var jsonData interface{}
				displayValue := string(value)

				if err := json.Unmarshal(value, &jsonData); err == nil {
					// It's valid JSON, pretty print it
					prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
					if err == nil {
						displayValue = string(prettyJSON)
					}
				}

				if show {
					fmt.Fprintf(c.Root().Writer, "Value: %s\n", displayValue)
				} else {
					fmt.Fprintf(c.Root().Writer, "Value: %s (use --show to display)\n", maskSecret(displayValue))
				}
			}

			return nil
		})
}

// SecretDeleteCommand creates the secret delete subcommand
func SecretDeleteCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("delete", "Delete a secret").
		SetUsage("Delete encrypted secret").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "Secret name",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "category",
				Aliases: []string{"c"},
				Usage:   "Secret category",
				Value:   "general",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			name := c.String("name")
			category := c.String("category")

			key := fmt.Sprintf("secret:%s:%s", category, name)

			if err := db.Delete([]byte(key)); err != nil {
				return fmt.Errorf("failed to delete secret: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Deleted secret '%s'\n", name)
			return nil
		})
}

// SecretListCommand creates the secret list subcommand
func SecretListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List all secrets").
		SetUsage("List all stored secrets").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:    "category",
				Aliases: []string{"c"},
				Usage:   "Filter by category",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			category := c.String("category")

			keys, _ := db.KeysPage(0, 1000)

			secrets := make([]string, 0)
			prefix := "secret:"
			if category != "" {
				prefix = fmt.Sprintf("secret:%s:", category)
			}

			for _, key := range keys {
				keyStr := string(key)
				if len(keyStr) >= len(prefix) && keyStr[:len(prefix)] == prefix {
					secretName := keyStr[len(prefix):]
					secrets = append(secrets, secretName)
				}
			}

			if len(secrets) == 0 {
				fmt.Fprintf(c.Root().Writer, "No secrets found\n")
				return nil
			}

			fmt.Fprintf(c.Root().Writer, "Found %d secrets:\n", len(secrets))
			for i, secret := range secrets {
				fmt.Fprintf(c.Root().Writer, "%d. %s\n", i+1, secret)
			}
			return nil
		})
}

// SecretRotateCommand creates the secret rotate subcommand
func SecretRotateCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("rotate", "Rotate a secret").
		SetUsage("Generate new random value for secret").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "Secret name",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "category",
				Aliases: []string{"c"},
				Usage:   "Secret category",
				Value:   "general",
			},
			&cli.IntFlag{
				Name:    "length",
				Aliases: []string{"l"},
				Usage:   "Length of generated secret (in bytes)",
				Value:   32,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			name := c.String("name")
			category := c.String("category")
			length := c.Int("length")

			// Generate new random secret
			secret := make([]byte, length)
			if _, err := rand.Read(secret); err != nil {
				return fmt.Errorf("failed to generate secret: %w", err)
			}

			newValue := hex.EncodeToString(secret)
			key := fmt.Sprintf("secret:%s:%s", category, name)

			if err := db.PutWithTTL([]byte(key), []byte(newValue), 0); err != nil {
				return fmt.Errorf("failed to rotate secret: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Rotated secret '%s'\n", name)
			fmt.Fprintf(c.Root().Writer, "  New value: %s\n", maskSecret(newValue))
			fmt.Fprintf(c.Root().Writer, "  Length: %d bytes\n", length)
			return nil
		})
}

func maskSecret(value string) string {
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "********" + value[len(value)-4:]
}

// splitDotNotation splits a key like "aws.secret_key" into ["aws", "secret_key"]
func splitDotNotation(key string) []string {
	return strings.Split(key, ".")
}

// getNestedValue retrieves a value from nested JSON using dot notation
// e.g., "aws.secret_key" from {"aws": {"secret_key": "val"}}
func getNestedValue(data map[string]interface{}, path []string) (interface{}, bool) {
	if len(path) == 0 {
		return nil, false
	}

	current := data
	for i, key := range path {
		val, exists := current[key]
		if !exists {
			return nil, false
		}

		// If this is the last key, return the value
		if i == len(path)-1 {
			return val, true
		}

		// Otherwise, navigate deeper
		nextMap, ok := val.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = nextMap
	}

	return nil, false
}

// setNestedValue sets a value in nested JSON using dot notation
// e.g., "aws.secret_key" = "val3" in {"aws": {"access_key": "val2"}}
func setNestedValue(data map[string]interface{}, path []string, value interface{}) {
	if len(path) == 0 {
		return
	}

	// If path is just one element, set it directly
	if len(path) == 1 {
		data[path[0]] = value
		return
	}

	current := data
	for i := 0; i < len(path)-1; i++ {
		key := path[i]
		val, exists := current[key]

		if !exists {
			// Create new nested map
			newMap := make(map[string]interface{})
			current[key] = newMap
			current = newMap
		} else {
			// Try to navigate to existing map
			nextMap, ok := val.(map[string]interface{})
			if !ok {
				// Value exists but is not a map, replace it with a map
				newMap := make(map[string]interface{})
				current[key] = newMap
				current = newMap
			} else {
				current = nextMap
			}
		}
	}

	// Set the final value
	current[path[len(path)-1]] = value
}

// parseJSONValue tries to parse a string as JSON, returns the value or the string itself
func parseJSONValue(value string) interface{} {
	var jsonValue interface{}
	if err := json.Unmarshal([]byte(value), &jsonValue); err == nil {
		return jsonValue
	}
	return value
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oarkflow/velocity"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	cfg := &velocity.Config{
		Path: getDBPath(),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	}

	db, err := velocity.NewWithConfig(*cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	ctx := context.Background()

	switch cmd {
	case "data":
		return handleData(db, ctx, args)
	case "secret":
		return handleSecret(db, args)
	case "object":
		return handleObject(db, args)
	case "envelope":
		return handleEnvelope(db, ctx, args)
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
	return nil
}

func printUsage() {
	fmt.Print(`Usage:
  velocity <command> [arguments]

Commands:
  data put <key> <value>      Store a key-value pair
  data get <key>            Retrieve a value
  secret set <name> <value>  Store a secret
  secret get <name>        Retrieve a secret
  object put <key>          Store an object
  object get <key>          Retrieve an object
  envelope create --label L   Create an envelope
  envelope get --id ID       Get envelope details
  envelope export --id ID --path PATH  Export envelope
  envelope import --path PATH        Import envelope
  envelope bundle create --label L --resource JSON  Create bundle
  envelope bundle list --id ID          List resources
  envelope bundle resolve --id ID        Resolve resources

Examples:
  velocity data put mykey myvalue
  velocity data get mykey
  velocity secret set api_key sk_12345
  velocity envelope create --label "Case 001" --type court_evidence
  velocity envelope bundle create --label "Evidence" --resource '[{"type":"file","name":"doc.pdf","path":"evidence/doc.pdf"}]'

Environment:
  VELOCITY_PATH   Database path (default: ./velocity_data)
`)
}

func getDBPath() string {
	if path := os.Getenv("VELOCITY_PATH"); path != "" {
		return path
	}
	return "./velocity_data"
}

func handleData(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity data put <key> <value> or velocity data get <key>")
	}
	subcmd := args[0]
	key := args[1]
	value := ""
	if len(args) >= 3 {
		value = args[2]
	}

	switch subcmd {
	case "put":
		if value == "" {
			return fmt.Errorf("usage: velocity data put <key> <value>")
		}
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			return fmt.Errorf("failed to put: %w", err)
		}
		fmt.Printf("Stored: %s\n", key)
	case "get":
		val, err := db.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}
		fmt.Println(string(val))
	default:
		return fmt.Errorf("unknown data command: %s", subcmd)
	}
	return nil
}

func handleSecret(db *velocity.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity secret set <name> <value> or velocity secret get <name>")
	}
	subcmd := args[0]
	name := args[1]
	value := ""
	if len(args) >= 3 {
		value = args[2]
	}
	key := fmt.Sprintf("secret:general:%s", name)

	switch subcmd {
	case "set":
		if value == "" {
			return fmt.Errorf("usage: velocity secret set <name> <value>")
		}
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}
		fmt.Printf("Stored secret: %s\n", name)
	case "get":
		val, err := db.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("secret not found: %s", name)
		}
		fmt.Println(string(val))
	default:
		return fmt.Errorf("unknown secret command: %s", subcmd)
	}
	return nil
}

func handleObject(db *velocity.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity object put <key> or velocity object get <key>")
	}
	subcmd := args[0]
	key := args[1]

	switch subcmd {
	case "put":
		content := []byte(key)
		_, err := db.StoreObject(key, "application/octet-stream", "system", content, nil)
		if err != nil {
			return fmt.Errorf("failed to store: %w", err)
		}
		fmt.Printf("Stored: %s\n", key)
	case "get":
		data, _, err := db.GetObject(key, "system")
		if err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}
		fmt.Println(string(data))
	default:
		return fmt.Errorf("unknown object command: %s", subcmd)
	}
	return nil
}

func parseFlags(args []string) (map[string]string, []string) {
	flags := make(map[string]string)
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				flags[strings.TrimPrefix(parts[0], "--")] = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[strings.TrimPrefix(parts[0], "--")] = args[i+1]
				i++
			}
		} else if strings.HasPrefix(arg, "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags[strings.TrimPrefix(arg, "-")] = args[i+1]
				i++
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return flags, positional
}

func handleEnvelope(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity envelope <create|get|export|import|bundle>")
	}
	subcmd := args[0]
	flags, _ := parseFlags(args[1:])

	switch subcmd {
	case "create":
		label := flags["label"]
		if label == "" {
			return fmt.Errorf("--label is required")
		}
		envType := flags["type"]
		if envType == "" {
			envType = "court_evidence"
		}
		kind := flags["kind"]
		if kind == "" {
			kind = "kv"
		}
		data := flags["data"]
		if data == "" {
			data = "{}"
		}

		payload := velocity.EnvelopePayload{Kind: kind}
		if kind == "kv" {
			payload.Value = json.RawMessage(data)
		}

		req := &velocity.EnvelopeRequest{
			Label:    label,
			Type:    velocity.EnvelopeType(envType),
			CreatedBy: "system",
			Payload: payload,
		}

		env, err := db.CreateEnvelope(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create: %w", err)
		}

		fmt.Printf("Created envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)
		fmt.Printf("  Type: %s\n", env.Type)

	case "get":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		fmt.Printf("Envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)
		fmt.Printf("  Type: %s\n", env.Type)
		fmt.Printf("  Kind: %s\n", env.Payload.Kind)
		fmt.Printf("  Status: %s\n", env.Status)
		fmt.Printf("  Created: %s\n", env.CreatedAt)

		if env.Payload.Kind == "bundle" && len(env.Payload.Resources) > 0 {
			fmt.Printf("\nResources (%d):\n", len(env.Payload.Resources))
			for _, res := range env.Payload.Resources {
				fmt.Printf("  - %s (%s)\n", res.Name, res.Type)
			}
		}

	case "export":
		id := flags["id"]
		path := flags["path"]
		if id == "" || path == "" {
			return fmt.Errorf("--id and --path are required")
		}

		if err := db.ExportEnvelope(ctx, id, path); err != nil {
			return fmt.Errorf("failed to export: %w", err)
		}

		fmt.Printf("Exported to: %s\n", path)

	case "import":
		path := flags["path"]
		if path == "" {
			return fmt.Errorf("--path is required")
		}

		env, err := db.ImportEnvelope(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to import: %w", err)
		}

		fmt.Printf("Imported envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)

	case "bundle":
		bundleArgs := args[1:]
		return handleEnvelopeBundle(db, ctx, bundleArgs)

	default:
		return fmt.Errorf("unknown envelope command: %s", subcmd)
	}
	return nil
}

func handleEnvelopeBundle(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity envelope bundle <create|list|resolve>")
	}
	bundleCmd := args[0]
	flags, _ := parseFlags(args[1:])

	switch bundleCmd {
	case "create":
		label := flags["label"]
		if label == "" {
			return fmt.Errorf("--label is required")
		}
		resourceJSON := flags["resource"]

		var resources []velocity.EnvelopeResource
		if resourceJSON != "" {
			if err := json.Unmarshal([]byte(resourceJSON), &resources); err != nil {
				return fmt.Errorf("failed to parse resources: %w", err)
			}
		}

		payload := velocity.EnvelopePayload{
			Kind:      "bundle",
			Resources: resources,
		}

		req := &velocity.EnvelopeRequest{
			Label:    label,
			Type:     velocity.EnvelopeTypeInvestigationRecord,
			CreatedBy: "system",
			Payload: payload,
		}

		env, err := db.CreateEnvelope(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create: %w", err)
		}

		fmt.Printf("Created bundle: %s\n", env.EnvelopeID)
		fmt.Printf("  Resources: %d\n", len(env.Payload.Resources))

	case "list":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		if len(env.Payload.Resources) == 0 {
			fmt.Println("No resources in bundle")
			return nil
		}

		fmt.Printf("Resources (%d):\n", len(env.Payload.Resources))
		for _, res := range env.Payload.Resources {
			fmt.Printf("  - %s (%s)\n", res.Name, res.Type)
		}

	case "resolve":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		resolved, err := db.ResolveResources(env.Payload)
		if err != nil {
			return fmt.Errorf("resolution failed: %w", err)
		}

		fmt.Printf("Resolved resources (%d):\n", len(resolved))
		for rid, data := range resolved {
			fmt.Printf("  %s: %d bytes\n", rid, len(data))
		}

	default:
		return fmt.Errorf("unknown bundle command: %s", bundleCmd)
	}
	return nil
}
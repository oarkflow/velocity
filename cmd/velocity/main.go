package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/oarkflow/velocity/pkg/compliance"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
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
	case "compliance":
		return handleCompliance(db, ctx, args)
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
  object preview <file> [object-path]  Store a file and open browser preview
  envelope create --label L   Create an envelope
  envelope get --id ID       Get envelope details
  envelope export --id ID --path PATH  Export envelope
  envelope import --path PATH        Import envelope
  envelope bundle create --label L --resource JSON  Create bundle
  envelope bundle list --id ID          List resources
  envelope bundle resolve --id ID        Resolve resources
  compliance tag --type TYPE [resource flags] --framework GDPR --class restricted
  compliance get --type TYPE [resource flags]
  compliance check --type TYPE [resource flags] --operation read --actor alice

Examples:
  velocity data put mykey myvalue
  velocity data get mykey
  velocity secret set api_key sk_12345
  velocity object preview ./notes.md docs/notes.md
  velocity envelope create --label "Case 001" --type court_evidence
  velocity envelope bundle create --label "Evidence" --resource '[{"type":"file","name":"doc.pdf","path":"evidence/doc.pdf"}]'
  velocity compliance tag --type sql_table --table patients --framework HIPAA --class restricted --encrypt
  velocity compliance tag --type secret --name api-key --framework GDPR --class confidential

Environment:
  VELOCITY_PATH   Database path (default: ./velocity_data)
`)
}

func handleCompliance(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity compliance <tag|get|check> --type TYPE [resource flags]")
	}
	subcmd := args[0]
	flags, _ := parseFlags(args[1:])
	ref, err := complianceRefFromFlags(flags)
	if err != nil {
		return err
	}
	ctm := db.ComplianceTagManager()
	if ctm == nil {
		ctm = velocity.NewComplianceTagManager(db)
		db.SetComplianceTagManager(ctm)
	}
	switch subcmd {
	case "tag":
		frameworks, err := parseComplianceFrameworks(flags["framework"])
		if err != nil {
			return err
		}
		dataClass := compliance.DataClassification(flags["class"])
		if dataClass == "" {
			dataClass = compliance.DataClassInternal
		}
		tag := &velocity.ComplianceTag{
			Frameworks:    frameworks,
			DataClass:     dataClass,
			Owner:         flags["owner"],
			Custodian:     flags["custodian"],
			EncryptionReq: flags["encrypt"] == "true",
			AuditLevel:    flags["audit"],
			AccessPolicy:  flags["access-policy"],
			CreatedBy:     flagDefault(flags, "created-by", "cli"),
		}
		if err := ctm.TagResource(ctx, ref, tag); err != nil {
			return err
		}
		fmt.Printf("Tagged %s\n", tag.ResourceID)
	case "get":
		tags := ctm.GetResourceTags(ref)
		return printJSON(tags)
	case "check":
		req := &velocity.ComplianceOperationRequest{
			Operation:       flagDefault(flags, "operation", "read"),
			Actor:           flags["actor"],
			Region:          flags["region"],
			SubjectID:       flags["subject-id"],
			Purpose:         flags["purpose"],
			Encrypted:       flags["encrypted"] == "true" || flags["encrypt"] == "true",
			MFAVerified:     flags["mfa"] == "true" || flags["mfa-verified"] == "true",
			CryptoAlgorithm: flags["crypto-algorithm"],
			Reason:          flags["reason"],
		}
		result, err := ctm.ValidateResourceOperation(ctx, ref, req)
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return fmt.Errorf("unknown compliance command: %s", subcmd)
	}
	return nil
}

func complianceRefFromFlags(flags map[string]string) (velocity.ComplianceResourceRef, error) {
	typ := velocity.ComplianceResourceType(flags["type"])
	ref := velocity.ComplianceResourceRef{Type: typ}
	switch typ {
	case velocity.ComplianceResourceKV:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceObject:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceBucket:
		ref.Bucket = requiredFlag(flags, "bucket")
	case velocity.ComplianceResourceFolder:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceSecret:
		ref.SecretName = requiredFlag(flags, "name")
	case velocity.ComplianceResourceSecretVersion:
		ref.SecretName = requiredFlag(flags, "name")
		ref.SecretVersion = requiredFlag(flags, "version")
	case velocity.ComplianceResourceSQLSchema:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
	case velocity.ComplianceResourceSQLTable:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
	case velocity.ComplianceResourceSQLColumn:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
		ref.SQLColumn = requiredFlag(flags, "column")
	case velocity.ComplianceResourceSQLRow:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
		ref.SQLRowKey = requiredFlag(flags, "row")
	default:
		return ref, fmt.Errorf("--type is required and must be one of kv, object, bucket, folder, secret, secret_version, sql_schema, sql_table, sql_column, sql_row")
	}
	if ref.CanonicalID() == "" {
		return ref, fmt.Errorf("missing resource flags for type %s", typ)
	}
	return ref, nil
}

func parseComplianceFrameworks(raw string) ([]compliance.Framework, error) {
	if raw == "" {
		return nil, fmt.Errorf("--framework is required")
	}
	parts := strings.Split(raw, ",")
	frameworks := make([]compliance.Framework, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch strings.ToUpper(part) {
		case "HIPAA":
			frameworks = append(frameworks, compliance.FrameworkHIPAA)
		case "GDPR":
			frameworks = append(frameworks, compliance.FrameworkGDPR)
		case "NIST", "NIST_800_53":
			frameworks = append(frameworks, compliance.FrameworkNIST)
		case "FIPS", "FIPS_140_2":
			frameworks = append(frameworks, compliance.FrameworkFIPS)
		case "PCI", "PCI_DSS":
			frameworks = append(frameworks, compliance.FrameworkPCIDSS)
		case "SOC2", "SOC2_TYPE2":
			frameworks = append(frameworks, compliance.FrameworkSOC2)
		case "ISO27001", "ISO_27001":
			frameworks = append(frameworks, compliance.FrameworkISO27001)
		default:
			return nil, fmt.Errorf("unknown framework: %s", part)
		}
	}
	return frameworks, nil
}

func requiredFlag(flags map[string]string, name string) string {
	return strings.TrimSpace(flags[name])
}

func flagDefault(flags map[string]string, name, fallback string) string {
	if value := strings.TrimSpace(flags[name]); value != "" {
		return value
	}
	return fallback
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
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
		return fmt.Errorf("usage: velocity object put <key>, velocity object get <key>, or velocity object preview <file> [object-path]")
	}
	subcmd := args[0]

	switch subcmd {
	case "put":
		key := args[1]
		content := []byte(key)
		_, err := db.StoreObject(key, "application/octet-stream", "system", content, nil)
		if err != nil {
			return fmt.Errorf("failed to store: %w", err)
		}
		fmt.Printf("Stored: %s\n", key)
	case "get":
		key := args[1]
		data, _, err := db.GetObject(key, "system")
		if err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}
		fmt.Println(string(data))
	case "preview", "render":
		return storeAndPreviewObject(db, args[1:])
	default:
		return fmt.Errorf("unknown object command: %s", subcmd)
	}
	return nil
}

func storeAndPreviewObject(db *velocity.DB, args []string) error {
	flags, positional := parseFlags(args)
	if len(positional) < 1 {
		return fmt.Errorf("usage: velocity object preview <file> [object-path] [--content-type TYPE] [--user USER] [--public]")
	}
	filePath := positional[0]
	objectPath := ""
	if len(positional) >= 2 {
		objectPath = positional[1]
	} else if flagPath := flags["path"]; flagPath != "" {
		objectPath = flagPath
	} else {
		objectPath = filepath.ToSlash(filepath.Base(filePath))
	}
	user := flags["user"]
	if user == "" {
		user = "system"
	}
	contentType := flags["content-type"]
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
	if flags["public"] == "true" || flags["public"] == "1" || flags["public"] == "yes" {
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
			} else {
				flags[strings.TrimPrefix(parts[0], "--")] = "true"
			}
		} else if strings.HasPrefix(arg, "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags[strings.TrimPrefix(arg, "-")] = args[i+1]
				i++
			} else {
				flags[strings.TrimPrefix(arg, "-")] = "true"
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
			Label:     label,
			Type:      velocity.EnvelopeType(envType),
			CreatedBy: "system",
			Payload:   payload,
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
			Label:     label,
			Type:      velocity.EnvelopeTypeInvestigationRecord,
			CreatedBy: "system",
			Payload:   payload,
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

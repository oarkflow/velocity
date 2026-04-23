package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/pkg/cli"
	"github.com/urfave/cli/v3"
)

// EnvelopeCommands creates the envelope command group
func EnvelopeCommands(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("envelope", "Secure envelope operations").
		SetCategory("Security").
		SetUsage("Manage secure evidence envelopes").
		SetPermission(velocitycli.PermissionAdmin)

	cmd.AddSubcommand(EnvelopeCreateCommand(db))
	cmd.AddSubcommand(EnvelopeGetCommand(db))
	cmd.AddSubcommand(EnvelopeListCommand(db))
	cmd.AddSubcommand(EnvelopeExportCommand(db))
	cmd.AddSubcommand(EnvelopeImportCommand(db))
	cmd.AddSubcommand(EnvelopeBundleCommand(db))

	return cmd
}

// EnvelopeCreateCommand creates the envelope create subcommand
func EnvelopeCreateCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("create", "Create a secure envelope").
		SetUsage("Create a secure evidence envelope").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "label",
				Aliases:  []string{"l"},
				Usage:    "Envelope label",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "type",
				Aliases:  []string{"t"},
				Usage:    "Envelope type (court_evidence, investigation_record, custody_proof, cctv_forensic_archive)",
				Value:   "court_evidence",
			},
			&cli.StringFlag{
				Name:     "kind",
				Aliases:  []string{"k"},
				Usage:    "Payload kind (file, kv, secret, bundle)",
				Value:   "kv",
			},
			&cli.StringFlag{
				Name:    "data",
				Usage:  "JSON data for kv payload",
				Value:  "{}",
			},
			&cli.StringFlag{
				Name:    "object-path",
				Usage: "Object storage path for file payload",
			},
			&cli.StringFlag{
				Name:    "secret-ref",
				Usage: "Secret reference (e.g., secret:category:name)",
			},
			&cli.StringFlag{
				Name:    "created-by",
				Usage: "Creator identity",
				Value:  "system",
			},
			&cli.StringFlag{
				Name:    "case-reference",
				Usage: "Case reference number",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			label := c.String("label")
			envType := velocity.EnvelopeType(c.String("type"))
			kind := c.String("kind")
			data := c.String("data")
			objectPath := c.String("object-path")
			secretRef := c.String("secret-ref")
			createdBy := c.String("created-by")
			caseRef := c.String("case-reference")

			var payload velocity.EnvelopePayload
			switch kind {
			case "file":
				payload = velocity.EnvelopePayload{
					Kind:       "file",
					ObjectPath:  objectPath,
				}
			case "secret":
				payload = velocity.EnvelopePayload{
					Kind:            "secret",
					SecretReference: secretRef,
				}
			case "kv":
				payload = velocity.EnvelopePayload{
					Kind:  "kv",
					Value: json.RawMessage(data),
				}
			case "bundle":
				payload = velocity.EnvelopePayload{
					Kind: "bundle",
				}
			default:
				return fmt.Errorf("unknown payload kind: %s", kind)
			}

			req := &velocity.EnvelopeRequest{
				Label:         label,
				Type:          envType,
				CreatedBy:     createdBy,
				CaseReference: caseRef,
				Payload:      payload,
			}

			env, err := db.CreateEnvelope(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create envelope: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Created envelope '%s'\n", env.EnvelopeID)
			fmt.Fprintf(c.Root().Writer, "  Type: %s\n", env.Type)
			fmt.Fprintf(c.Root().Writer, "  Kind: %s\n", env.Payload.Kind)
			fmt.Fprintf(c.Root().Writer, "  Status: %s\n", env.Status)

			return nil
		})
}

// EnvelopeGetCommand creates the envelope get subcommand
func EnvelopeGetCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("get", "Get envelope details").
		SetUsage("Get envelope details by ID").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "id",
				Aliases:  []string{"i"},
				Usage:    "Envelope ID",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "show-payload",
				Usage: "Show payload content",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "show-custody",
				Usage: "Show custody chain",
				Value: false,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			id := c.String("id")
			showPayload := c.Bool("show-payload")
			showCustody := c.Bool("show-custody")

			env, err := db.LoadEnvelope(ctx, id)
			if err != nil {
				return fmt.Errorf("envelope not found: %s", id)
			}

			fmt.Fprintf(c.Root().Writer, "Envelope: %s\n", env.EnvelopeID)
			fmt.Fprintf(c.Root().Writer, "  Label: %s\n", env.Label)
			fmt.Fprintf(c.Root().Writer, "  Type: %s\n", env.Type)
			fmt.Fprintf(c.Root().Writer, "  Kind: %s\n", env.Payload.Kind)
			fmt.Fprintf(c.Root().Writer, "  Status: %s\n", env.Status)
			fmt.Fprintf(c.Root().Writer, "  Created: %s\n", env.CreatedAt)
			fmt.Fprintf(c.Root().Writer, "  Created By: %s\n", env.CreatedBy)

			if showPayload {
				fmt.Fprintf(c.Root().Writer, "\nPayload:\n")
				if env.Payload.Kind == "bundle" && len(env.Payload.Resources) > 0 {
					for _, res := range env.Payload.Resources {
						fmt.Fprintf(c.Root().Writer, "  - %s (%s)\n", res.Name, res.Type)
					}
				} else {
					fmt.Fprintf(c.Root().Writer, "  %s\n", string(env.Payload.Value))
				}
			}

			if showCustody && len(env.CustodyLedger) > 0 {
				fmt.Fprintf(c.Root().Writer, "\nCustody Chain:\n")
				for _, e := range env.CustodyLedger {
					fmt.Fprintf(c.Root().Writer, "  %d: %s by %s\n", e.Sequence, e.Action, e.Actor)
				}
			}

			return nil
		})
}

// EnvelopeListCommand creates the envelope list subcommand
func EnvelopeListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List envelopes").
		SetUsage("List all envelopes").
		SetPermission(velocitycli.PermissionAdmin).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			fmt.Fprintf(c.Root().Writer, "Use 'envelope get <id>' to retrieve individual envelope details\n")
			fmt.Fprintf(c.Root().Writer, "Envelopes are stored at: <db-path>/envelopes/*.sec\n")
			return nil
		})
}

// EnvelopeExportCommand creates the envelope export subcommand
func EnvelopeExportCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("export", "Export envelope to file").
		SetUsage("Export envelope to a .sec file").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "id",
				Aliases:  []string{"i"},
				Usage:    "Envelope ID",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Export path",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			id := c.String("id")
			path := c.String("path")

			if !strings.HasSuffix(path, ".sec") {
				path = path + ".sec"
			}

			if err := db.ExportEnvelope(ctx, id, path); err != nil {
				return fmt.Errorf("failed to export envelope: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Exported envelope to %s\n", path)
			return nil
		})
}

// EnvelopeImportCommand creates the envelope import subcommand
func EnvelopeImportCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("import", "Import envelope from file").
		SetUsage("Import envelope from a .sec file").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Usage:    "Import file path",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			path := c.String("path")

			env, err := db.ImportEnvelope(ctx, path)
			if err != nil {
				return fmt.Errorf("failed to import envelope: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Imported envelope %s\n", env.EnvelopeID)
			fmt.Fprintf(c.Root().Writer, "  Label: %s\n", env.Label)
			fmt.Fprintf(c.Root().Writer, "  Type: %s\n", env.Type)

			return nil
		})
}

// EnvelopeBundleCommand creates the envelope bundle subcommand for managing resources
func EnvelopeBundleCommand(db *velocity.DB) velocitycli.CommandBuilder {
	cmd := velocitycli.NewBaseCommand("bundle", "Manage envelope resource bundles").
		SetUsage("Bundle multiple resources in an envelope").
		SetPermission(velocitycli.PermissionAdmin)

	cmd.AddSubcommand(EnvelopeBundleCreateCommand(db))
	cmd.AddSubcommand(EnvelopeBundleListCommand(db))
	cmd.AddSubcommand(EnvelopeBundleResolveCommand(db))

	return cmd
}

// EnvelopeBundleCreateCommand creates an envelope with bundle resources in one step
func EnvelopeBundleCreateCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("create", "Create envelope with bundle resources").
		SetUsage("Create envelope with multiple resources (file, secret, kv)").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "label",
				Aliases:  []string{"l"},
				Usage:    "Envelope label",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "type",
				Aliases:  []string{"t"},
				Usage:    "Envelope type",
				Value:   "investigation_record",
			},
			&cli.StringFlag{
				Name:    "resource",
				Aliases: []string{"r"},
				Usage:   "Resources as JSON array (e.g., '[{\"type\":\"file\",\"name\":\"doc.pdf\",\"path\":\"evidence/doc.pdf\"}]')",
			},
			&cli.StringFlag{
				Name:    "created-by",
				Usage:  "Creator identity",
				Value:  "system",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			label := c.String("label")
			envType := velocity.EnvelopeType(c.String("type"))
			resourceJSON := c.String("resource")
			createdBy := c.String("created-by")

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
				Type:     envType,
				CreatedBy: createdBy,
				Payload:  payload,
			}

			env, err := db.CreateEnvelope(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create envelope: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Created bundle envelope '%s'\n", env.EnvelopeID)
			fmt.Fprintf(c.Root().Writer, "  Resources: %d\n", len(env.Payload.Resources))

			return nil
		})
}
func EnvelopeBundleAddCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("add", "Add resource to bundle").
		SetUsage("Add a file, secret, or KV resource to envelope bundle").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "envelope-id",
				Aliases:  []string{"e"},
				Usage:    "Envelope ID",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "Resource name",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "type",
				Aliases:  []string{"t"},
				Usage:    "Resource type (file, secret, kv)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "path",
				Usage:  "Object storage path (for file type)",
			},
			&cli.StringFlag{
				Name:    "secret-ref",
				Usage:  "Secret reference (for secret type)",
			},
			&cli.StringFlag{
				Name:    "key",
				Usage:  "Key (for kv type)",
			},
			&cli.StringFlag{
				Name:    "value",
				Usage:  "Value (for kv type)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			envelopeID := c.String("envelope-id")
			name := c.String("name")
			resType := c.String("type")
			path := c.String("path")
			secretRef := c.String("secret-ref")
			key := c.String("key")
			value := c.String("value")

			env, err := db.LoadEnvelope(ctx, envelopeID)
			if err != nil {
				return fmt.Errorf("envelope not found: %s", envelopeID)
			}

			resource := velocity.EnvelopeResource{
				ID:     fmt.Sprintf("res-%d", len(env.Payload.Resources)+1),
				Type:   resType,
				Name:   name,
				Path:   path,
				SecretRef: secretRef,
				Key:    key,
			}

			if value != "" {
				resource.Value = json.RawMessage(value)
			}

			env.Payload.Resources = append(env.Payload.Resources, resource)
			env.Payload.Kind = "bundle"

			if err := db.UpdateEnvelope(ctx, env); err != nil {
				return fmt.Errorf("failed to update envelope: %w", err)
			}

			fmt.Fprintf(c.Root().Writer, "✓ Added resource '%s' to envelope %s\n", name, envelopeID)
			fmt.Fprintf(c.Root().Writer, "  Total resources: %d\n", len(env.Payload.Resources))

			return nil
		})
}

// EnvelopeBundleListCommand lists resources in an envelope bundle
func EnvelopeBundleListCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("list", "List bundle resources").
		SetUsage("List resources in envelope bundle").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "envelope-id",
				Aliases:  []string{"e"},
				Usage:    "Envelope ID",
				Required: true,
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			envelopeID := c.String("envelope-id")

			env, err := db.LoadEnvelope(ctx, envelopeID)
			if err != nil {
				return fmt.Errorf("envelope not found: %s", envelopeID)
			}

			if len(env.Payload.Resources) == 0 {
				fmt.Fprintf(c.Root().Writer, "No resources in bundle\n")
				return nil
			}

			fmt.Fprintf(c.Root().Writer, "Resources in bundle (%d):\n", len(env.Payload.Resources))
			for _, res := range env.Payload.Resources {
				var location string
				switch res.Type {
				case "file":
					location = res.Path
				case "secret":
					location = res.SecretRef
				case "kv":
					location = res.Key
				}
				fmt.Fprintf(c.Root().Writer, "  %s: %s (%s)\n", res.ID, res.Name, location)
			}

			return nil
		})
}

// EnvelopeBundleResolveCommand resolves and displays resource content
func EnvelopeBundleResolveCommand(db *velocity.DB) velocitycli.CommandBuilder {
	return velocitycli.NewBaseCommand("resolve", "Resolve bundle resources").
		SetUsage("Resolve and display resource contents").
		SetPermission(velocitycli.PermissionAdmin).
		AddFlags(
			&cli.StringFlag{
				Name:     "envelope-id",
				Aliases:  []string{"e"},
				Usage:    "Envelope ID",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "resource-id",
				Aliases:  []string{"r"},
				Usage:   "Specific resource ID (optional)",
			},
		).
		SetAction(func(ctx context.Context, c *cli.Command) error {
			envelopeID := c.String("envelope-id")
			resourceID := c.String("resource-id")

			env, err := db.LoadEnvelope(ctx, envelopeID)
			if err != nil {
				return fmt.Errorf("envelope not found: %s", envelopeID)
			}

			resolved, err := db.ResolveResources(env.Payload)
			if err != nil {
				return fmt.Errorf("failed to resolve resources: %w", err)
			}

			if resourceID != "" {
				data, ok := resolved[resourceID]
				if !ok {
					return fmt.Errorf("resource not found: %s", resourceID)
				}
				fmt.Fprintf(c.Root().Writer, "Resource %s:\n%s\n", resourceID, string(data))
				return nil
			}

			fmt.Fprintf(c.Root().Writer, "Resolved resources:\n")
			for id, data := range resolved {
				fmt.Fprintf(c.Root().Writer, "  %s: %d bytes\n", id, len(data))
			}

			return nil
		})
}
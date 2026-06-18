package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"
)

func envelopeCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "envelope",
		Usage: "Secure envelope operations",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a secure envelope",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "label", Aliases: []string{"l"}, Usage: "Envelope label", Required: true},
					&cli.StringFlag{Name: "type", Aliases: []string{"t"}, Usage: "Envelope type", Value: "court_evidence"},
					&cli.StringFlag{Name: "kind", Aliases: []string{"k"}, Usage: "Payload kind (file, kv, secret, bundle)", Value: "kv"},
					&cli.StringFlag{Name: "data", Usage: "JSON data for kv payload", Value: "{}"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					payload := velocity.EnvelopePayload{Kind: cmd.String("kind")}
					if cmd.String("kind") == "kv" {
						payload.Value = json.RawMessage(cmd.String("data"))
					}
					req := &velocity.EnvelopeRequest{
						Label:     cmd.String("label"),
						Type:      velocity.EnvelopeType(cmd.String("type")),
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
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get envelope details",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Aliases: []string{"i"}, Usage: "Envelope ID", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.String("id")
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
					return nil
				},
			},
			{
				Name:  "export",
				Usage: "Export envelope to file",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Aliases: []string{"i"}, Usage: "Envelope ID", Required: true},
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Export path", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if err := db.ExportEnvelope(ctx, cmd.String("id"), cmd.String("path")); err != nil {
						return fmt.Errorf("failed to export: %w", err)
					}
					fmt.Printf("Exported to: %s\n", cmd.String("path"))
					return nil
				},
			},
			{
				Name:  "import",
				Usage: "Import envelope from file",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Import file path", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					env, err := db.ImportEnvelope(ctx, cmd.String("path"))
					if err != nil {
						return fmt.Errorf("failed to import: %w", err)
					}
					fmt.Printf("Imported envelope: %s\n", env.EnvelopeID)
					fmt.Printf("  Label: %s\n", env.Label)
					return nil
				},
			},
			{
				Name:  "bundle",
				Usage: "Manage envelope resource bundles",
				Commands: []*cli.Command{
					{
						Name:  "create",
						Usage: "Create envelope with bundle resources",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "label", Aliases: []string{"l"}, Usage: "Envelope label", Required: true},
							&cli.StringFlag{Name: "resource", Aliases: []string{"r"}, Usage: "Resources as JSON array"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							var resources []velocity.EnvelopeResource
							if r := cmd.String("resource"); r != "" {
								if err := json.Unmarshal([]byte(r), &resources); err != nil {
									return fmt.Errorf("failed to parse resources: %w", err)
								}
							}
							req := &velocity.EnvelopeRequest{
								Label:     cmd.String("label"),
								Type:      velocity.EnvelopeTypeInvestigationRecord,
								CreatedBy: "system",
								Payload:   velocity.EnvelopePayload{Kind: "bundle", Resources: resources},
							}
							env, err := db.CreateEnvelope(ctx, req)
							if err != nil {
								return fmt.Errorf("failed to create: %w", err)
							}
							fmt.Printf("Created bundle: %s\n", env.EnvelopeID)
							fmt.Printf("  Resources: %d\n", len(env.Payload.Resources))
							return nil
						},
					},
					{
						Name:  "list",
						Usage: "List bundle resources",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Aliases: []string{"i"}, Usage: "Envelope ID", Required: true},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							env, err := db.LoadEnvelope(ctx, cmd.String("id"))
							if err != nil {
								return fmt.Errorf("envelope not found: %s", cmd.String("id"))
							}
							if len(env.Payload.Resources) == 0 {
								fmt.Println("No resources in bundle")
								return nil
							}
							fmt.Printf("Resources (%d):\n", len(env.Payload.Resources))
							for _, res := range env.Payload.Resources {
								fmt.Printf("  - %s (%s)\n", res.Name, res.Type)
							}
							return nil
						},
					},
					{
						Name:  "resolve",
						Usage: "Resolve bundle resources",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Aliases: []string{"i"}, Usage: "Envelope ID", Required: true},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							env, err := db.LoadEnvelope(ctx, cmd.String("id"))
							if err != nil {
								return fmt.Errorf("envelope not found: %s", cmd.String("id"))
							}
							resolved, err := db.ResolveResources(env.Payload)
							if err != nil {
								return fmt.Errorf("resolution failed: %w", err)
							}
							fmt.Printf("Resolved resources (%d):\n", len(resolved))
							for rid, data := range resolved {
								fmt.Printf("  %s: %d bytes\n", rid, len(data))
							}
							return nil
						},
					},
				},
			},
		},
	}
}

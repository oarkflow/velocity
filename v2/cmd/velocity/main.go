// Command velocity is the Velocity v2 embedded CLI: it boots the same
// kernel + plugin set as cmd/velocityd for the duration of a single
// command invocation (boot, run one command, graceful shutdown), then
// exits — there is no server, no client/server round trip. This mirrors
// v1's cmd/velocity design where the CLI used the DB directly in-process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/internal/bootstrap"
	"github.com/oarkflow/velocity/v2/kernel"
)

func main() {
	app := &cli.Command{
		Name:  "velocity",
		Usage: "Velocity v2 embedded CLI (boots the kernel in-process for one command, then exits)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "manifest",
				Value: "config/velocityd.example.json",
				Usage: "path to the plugin manifest JSON file",
			},
		},
		Commands: []*cli.Command{
			kvCmd(),
			secretCmd(),
			objectCmd(),
			complianceCmd(),
			searchCmd(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "velocity:", err)
		os.Exit(1)
	}
}

// withKernel loads the manifest named by --manifest, boots every plugin
// bootstrap.AllPlugins() knows about (only the ones the manifest enables
// actually start), runs fn against the live kernel, then gracefully shuts
// down — regardless of whether fn returned an error — before returning.
func withKernel(ctx context.Context, cmd *cli.Command, fn func(ctx context.Context, k *kernel.Kernel) error) error {
	manifestPath := cmd.Root().String("manifest")

	manifest, err := kernel.LoadManifestJSON(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest %q: %w", manifestPath, err)
	}

	k := kernel.New(manifest)
	if err := k.Boot(ctx, bootstrap.AllPlugins(manifest), manifest.Enabled()); err != nil {
		return fmt.Errorf("booting kernel: %w", err)
	}

	fnErr := fn(ctx, k)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if shutErr := k.Shutdown(shutdownCtx); shutErr != nil && fnErr == nil {
		return fmt.Errorf("shutting down: %w", shutErr)
	}
	return fnErr
}

func lookup[T any](k *kernel.Kernel, name string) (T, error) {
	var zero T
	svc, ok := k.Registry().Lookup(name)
	if !ok {
		return zero, fmt.Errorf("service %q is not registered — is its plugin enabled in the manifest?", name)
	}
	typed, ok := svc.(T)
	if !ok {
		return zero, fmt.Errorf("service %q does not implement the expected interface", name)
	}
	return typed, nil
}

// --- kv ---

func kvCmd() *cli.Command {
	return &cli.Command{
		Name:  "kv",
		Usage: "key-value operations",
		Commands: []*cli.Command{
			{
				Name:      "put",
				Usage:     "put <key> <value>",
				ArgsUsage: "<key> <value>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return errors.New("usage: kv put <key> <value>")
					}
					key, value := cmd.Args().Get(0), cmd.Args().Get(1)
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.KVService](k, "kv")
						if err != nil {
							return err
						}
						if err := svc.Put(ctx, key, []byte(value)); err != nil {
							return err
						}
						fmt.Println("OK")
						return nil
					})
				},
			},
			{
				Name:      "get",
				Usage:     "get <key>",
				ArgsUsage: "<key>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return errors.New("usage: kv get <key>")
					}
					key := cmd.Args().Get(0)
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.KVService](k, "kv")
						if err != nil {
							return err
						}
						value, ok, err := svc.Get(ctx, key)
						if err != nil {
							return err
						}
						if !ok {
							return fmt.Errorf("key %q not found", key)
						}
						fmt.Println(string(value))
						return nil
					})
				},
			},
			{
				Name:      "delete",
				Usage:     "delete <key>",
				ArgsUsage: "<key>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return errors.New("usage: kv delete <key>")
					}
					key := cmd.Args().Get(0)
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.KVService](k, "kv")
						if err != nil {
							return err
						}
						if err := svc.Delete(ctx, key); err != nil {
							return err
						}
						fmt.Println("OK")
						return nil
					})
				},
			},
		},
	}
}

// --- secret ---

func secretCmd() *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "secret management",
		Commands: []*cli.Command{
			{
				Name:      "set",
				Usage:     "set <name> <value>",
				ArgsUsage: "<name> <value>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return errors.New("usage: secret set <name> <value>")
					}
					name, value := cmd.Args().Get(0), cmd.Args().Get(1)
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.SecretService](k, "secret")
						if err != nil {
							return err
						}
						version, err := svc.Set(ctx, name, []byte(value))
						if err != nil {
							return err
						}
						fmt.Printf("OK (version %d)\n", version)
						return nil
					})
				},
			},
			{
				Name:      "get",
				Usage:     "get <name> [version]",
				ArgsUsage: "<name> [version]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return errors.New("usage: secret get <name> [version]")
					}
					name := cmd.Args().Get(0)
					version := 0
					if cmd.Args().Len() == 2 {
						if _, err := fmt.Sscanf(cmd.Args().Get(1), "%d", &version); err != nil {
							return fmt.Errorf("invalid version %q: %w", cmd.Args().Get(1), err)
						}
					}
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.SecretService](k, "secret")
						if err != nil {
							return err
						}
						value, err := svc.Get(ctx, name, version)
						if err != nil {
							return err
						}
						fmt.Println(string(value))
						return nil
					})
				},
			},
		},
	}
}

// --- object ---

func objectCmd() *cli.Command {
	return &cli.Command{
		Name:  "object",
		Usage: "object storage operations",
		Commands: []*cli.Command{
			{
				Name:      "put",
				Usage:     "put <bucket> <key> <file-path>",
				ArgsUsage: "<bucket> <key> <file-path>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 3 {
						return errors.New("usage: object put <bucket> <key> <file-path>")
					}
					bucket, key, path := cmd.Args().Get(0), cmd.Args().Get(1), cmd.Args().Get(2)
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.ObjectService](k, "object")
						if err != nil {
							return err
						}
						if err := svc.CreateBucket(ctx, bucket); err != nil {
							// Bucket may already exist — proceed; PutObject will
							// surface a clearer error if the bucket truly can't
							// be used.
							_ = err
						}
						meta, err := svc.PutObject(ctx, bucket, key, f, api.ObjectMeta{})
						if err != nil {
							return err
						}
						fmt.Printf("OK (version %s, size %d)\n", meta.VersionID, meta.Size)
						return nil
					})
				},
			},
			{
				Name:      "get",
				Usage:     "get <bucket> <key> [version] -o <output-path>",
				ArgsUsage: "<bucket> <key> [version]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "o", Usage: "output file path (default: stdout)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 || cmd.Args().Len() > 3 {
						return errors.New("usage: object get <bucket> <key> [version] -o <output-path>")
					}
					bucket, key := cmd.Args().Get(0), cmd.Args().Get(1)
					versionID := ""
					if cmd.Args().Len() == 3 {
						versionID = cmd.Args().Get(2)
					}
					outPath := cmd.String("o")
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.ObjectService](k, "object")
						if err != nil {
							return err
						}
						r, _, err := svc.GetObject(ctx, bucket, key, versionID)
						if err != nil {
							return err
						}
						defer r.Close()

						out := io.Writer(os.Stdout)
						if outPath != "" {
							f, err := os.Create(outPath)
							if err != nil {
								return err
							}
							defer f.Close()
							out = f
						}
						_, err = io.Copy(out, r)
						return err
					})
				},
			},
			{
				Name:      "list",
				Usage:     "list <bucket> [prefix]",
				ArgsUsage: "<bucket> [prefix]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return errors.New("usage: object list <bucket> [prefix]")
					}
					bucket := cmd.Args().Get(0)
					prefix := ""
					if cmd.Args().Len() == 2 {
						prefix = cmd.Args().Get(1)
					}
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.ObjectService](k, "object")
						if err != nil {
							return err
						}
						objs, err := svc.ListObjects(ctx, bucket, prefix)
						if err != nil {
							return err
						}
						for _, o := range objs {
							fmt.Printf("%s\t%d\t%s\n", o.Key, o.Size, o.VersionID)
						}
						return nil
					})
				},
			},
		},
	}
}

// --- compliance ---

func complianceCmd() *cli.Command {
	return &cli.Command{
		Name:  "compliance",
		Usage: "compliance/audit operations",
		Commands: []*cli.Command{
			{
				Name:  "audit-verify",
				Usage: "verify the audit hash chain is intact",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.ComplianceService](k, "compliance")
						if err != nil {
							return err
						}
						if err := svc.VerifyChain(ctx); err != nil {
							fmt.Println("FAIL:", err)
							return err
						}
						fmt.Println("PASS: audit chain intact")
						return nil
					})
				},
			},
		},
	}
}

// --- search ---

func searchCmd() *cli.Command {
	return &cli.Command{
		Name:  "search",
		Usage: "full-text search operations",
		Commands: []*cli.Command{
			{
				Name:      "index",
				Usage:     "index <key> <json-fields>",
				ArgsUsage: "<key> <json-fields>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return errors.New(`usage: search index <key> <json-fields>  (e.g. '{"title":"hello"}')`)
					}
					key, rawFields := cmd.Args().Get(0), cmd.Args().Get(1)
					fields, err := parseFields(rawFields)
					if err != nil {
						return err
					}
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.SearchIndex](k, "search.fulltext")
						if err != nil {
							return err
						}
						if err := svc.Index(ctx, key, fields); err != nil {
							return err
						}
						fmt.Println("OK")
						return nil
					})
				},
			},
			{
				Name:      "query",
				Usage:     "query <query> [limit]",
				ArgsUsage: "<query> [limit]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return errors.New("usage: search query <query> [limit]")
					}
					q := cmd.Args().Get(0)
					limit := 10
					if cmd.Args().Len() == 2 {
						if _, err := fmt.Sscanf(cmd.Args().Get(1), "%d", &limit); err != nil {
							return fmt.Errorf("invalid limit %q: %w", cmd.Args().Get(1), err)
						}
					}
					return withKernel(ctx, cmd, func(ctx context.Context, k *kernel.Kernel) error {
						svc, err := lookup[api.SearchIndex](k, "search.fulltext")
						if err != nil {
							return err
						}
						hits, err := svc.Query(ctx, q, limit)
						if err != nil {
							return err
						}
						for _, h := range hits {
							fmt.Printf("%s\t%.4f\n", h.Key, h.Score)
						}
						return nil
					})
				},
			},
		},
	}
}

func parseFields(raw string) (map[string]any, error) {
	fields := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("invalid JSON fields %q: %w", raw, err)
	}
	return fields, nil
}

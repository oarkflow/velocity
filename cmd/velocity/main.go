package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	encrypt := encryptionRequested(os.Args[1:])

	cfg := &velocity.Config{
		Path:             getDBPath(),
		EnableEncryption: encrypt,
	}
	if encrypt {
		cfg.MasterKeyConfig = velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		}
	}

	db, err := velocity.NewWithConfig(*cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	app := buildApp(db)
	return app.Run(context.Background(), os.Args)
}

// encryptionRequested resolves the encryption toggle before the CLI parses
// flags, because the database must be opened first. Encryption is disabled by
// default; VELOCITY_ENCRYPT or a global --encrypt flag (before the
// subcommand) turns it on.
func encryptionRequested(args []string) bool {
	enabled := false
	if raw := os.Getenv("VELOCITY_ENCRYPT"); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			enabled = v
		}
	}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			break // global flags end at the first subcommand
		}
		switch arg {
		case "--encrypt", "--encrypt=true":
			enabled = true
		case "--encrypt=false":
			enabled = false
		}
	}
	return enabled
}

func buildApp(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:                 "velocity",
		Usage:                "Secure database CLI",
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "encrypt",
				Usage:   "Enable at-rest encryption (disabled by default; also via VELOCITY_ENCRYPT)",
				Sources: cli.EnvVars("VELOCITY_ENCRYPT"),
			},
		},
		Commands: []*cli.Command{
			dataCmd(db),
			secretCmd(db),
			objectCmd(db),
			envelopeCmd(db),
			complianceCmd(db),
			kgCmd(db),
		},
	}
}

func getDBPath() string {
	if path := os.Getenv("VELOCITY_PATH"); path != "" {
		return path
	}
	return "./velocity_data"
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func parseIntDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseFloatDefault(raw string, fallback float64) float64 {
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitCSVTrim(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

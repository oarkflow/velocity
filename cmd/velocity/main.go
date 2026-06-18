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

	app := buildApp(db)
	return app.Run(context.Background(), os.Args)
}

func buildApp(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:                 "velocity",
		Usage:                "Secure database CLI",
		EnableShellCompletion: true,
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

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	apppkg "github.com/oarkflow/velocity/internal/secretr/cli/app"
	"github.com/urfave/cli/v3"
)

type commandDoc struct {
	Path        string
	Usage       string
	Description string
	ArgsUsage   string
	Flags       []flagDoc
}

type flagDoc struct {
	Name      string
	Aliases   []string
	Type      string
	Required  bool
	Usage     string
	Default   string
	Canonical string
}

func main() {
	outPath := filepath.Join("internal", "secretr", "COMMANDS.md")
	root := apppkg.BuildCLIRootForAuthz()
	cmds := collectDocs(root, "")
	sort.Slice(cmds, func(i, j int) bool {
		return cmds[i].Path < cmds[j].Path
	})

	var b bytes.Buffer
	b.WriteString("# Secretr Command Reference\n\n")
	b.WriteString("This file is auto-generated from the live CLI command tree.\n")
	b.WriteString("Do not edit manually. Regenerate with:\n\n")
	b.WriteString("```bash\n")
	b.WriteString("go run ./internal/secretr/cmd/gendocs\n")
	b.WriteString("```\n\n")
	b.WriteString("## Usage Notes\n")
	b.WriteString("- Commands are grouped by top-level namespace.\n")
	b.WriteString("- `Required` flags are mandatory.\n")
	b.WriteString("- `Minimal Example` is intended to be copy-paste runnable with sample values.\n")
	b.WriteString("- For environment-specific values (IDs, files, emails), replace sample values as needed.\n\n")

	grouped := map[string][]commandDoc{}
	for _, c := range cmds {
		top := strings.SplitN(c.Path, " ", 2)[0]
		grouped[top] = append(grouped[top], c)
	}
	groups := make([]string, 0, len(grouped))
	for g := range grouped {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	for _, g := range groups {
		b.WriteString("## " + g + "\n\n")
		for _, c := range grouped[g] {
			writeCommandDoc(&b, c)
		}
	}

	if err := os.WriteFile(outPath, b.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}
}

func collectDocs(cmd *cli.Command, prefix string) []commandDoc {
	if cmd == nil {
		return nil
	}
	var out []commandDoc
	for _, sub := range cmd.Commands {
		if sub == nil {
			continue
		}
		name := strings.TrimSpace(sub.Name)
		if name == "" || name == "help" || name == "h" {
			continue
		}
		path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
		doc := commandDoc{
			Path:        path,
			Usage:       strings.TrimSpace(sub.Usage),
			Description: strings.TrimSpace(sub.Description),
			ArgsUsage:   strings.TrimSpace(sub.ArgsUsage),
			Flags:       collectFlagDocs(sub.Flags),
		}
		out = append(out, doc)
		out = append(out, collectDocs(sub, path)...)
	}
	return out
}

func collectFlagDocs(flags []cli.Flag) []flagDoc {
	out := make([]flagDoc, 0, len(flags))
	for _, f := range flags {
		if f == nil {
			continue
		}
		names := f.Names()
		if len(names) == 0 {
			continue
		}
		fd := flagDoc{
			Name:      names[0],
			Aliases:   names[1:],
			Type:      "string",
			Usage:     strings.TrimSpace(f.String()),
			Canonical: names[0],
		}
		switch v := f.(type) {
		case *cli.StringFlag:
			fd.Type = "string"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			fd.Default = v.Value
		case *cli.StringSliceFlag:
			fd.Type = "string[]"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			if len(v.Value) > 0 {
				fd.Default = strings.Join(v.Value, ",")
			}
		case *cli.IntFlag:
			fd.Type = "int"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			fd.Default = strconv.Itoa(v.Value)
		case *cli.BoolFlag:
			fd.Type = "bool"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			fd.Default = strconv.FormatBool(v.Value)
		case *cli.DurationFlag:
			fd.Type = "duration"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			fd.Default = v.Value.String()
		case *cli.Float64Flag:
			fd.Type = "float64"
			fd.Required = v.Required
			fd.Usage = strings.TrimSpace(v.Usage)
			fd.Default = strconv.FormatFloat(v.Value, 'f', -1, 64)
		}
		out = append(out, fd)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func writeCommandDoc(b *bytes.Buffer, c commandDoc) {
	b.WriteString("### secretr " + c.Path + "\n\n")
	if c.Usage != "" {
		b.WriteString("- **What**: " + c.Usage + "\n")
	}
	if c.Description != "" {
		b.WriteString("- **Description**: " + c.Description + "\n")
	}
	if c.ArgsUsage != "" {
		b.WriteString("- **Arguments**: `" + c.ArgsUsage + "`\n")
	}
	if c.Usage != "" || c.Description != "" || c.ArgsUsage != "" {
		b.WriteString("\n")
	}

	if len(c.Flags) == 0 {
		b.WriteString("Flags: none\n\n")
	} else {
		b.WriteString("| Flag | Type | Required | Default | Description |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, f := range c.Flags {
			name := "`--" + f.Name + "`"
			if len(f.Aliases) > 0 {
				als := make([]string, 0, len(f.Aliases))
				for _, a := range f.Aliases {
					als = append(als, "`-"+a+"`")
				}
				name += " (" + strings.Join(als, ", ") + ")"
			}
			def := f.Default
			if def == "" {
				def = "-"
			}
			req := "no"
			if f.Required {
				req = "yes"
			}
			desc := strings.ReplaceAll(f.Usage, "|", "\\|")
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", name, f.Type, req, "`"+def+"`", desc))
		}
		b.WriteString("\n")
	}

	b.WriteString("Minimal Example:\n\n")
	b.WriteString("```bash\n")
	b.WriteString(exampleFor(c, false) + "\n")
	b.WriteString("```\n\n")

	if len(c.Flags) > 0 {
		b.WriteString("Full Flags Example:\n\n")
		b.WriteString("```bash\n")
		b.WriteString(exampleFor(c, true) + "\n")
		b.WriteString("```\n\n")
	}
}

func exampleFor(c commandDoc, includeOptional bool) string {
	parts := []string{"secretr", c.Path}

	for _, f := range c.Flags {
		if !f.Required && !includeOptional {
			continue
		}
		if !f.Required && includeOptional && f.Type == "bool" {
			// Include at most one optional bool for readability.
			continue
		}
		flagToken := "--" + f.Canonical
		switch f.Type {
		case "bool":
			if f.Required || includeOptional {
				parts = append(parts, flagToken)
			}
		case "string[]":
			parts = append(parts, flagToken+"="+sampleValue(c.Path, f.Name, f.Type))
			if includeOptional {
				parts = append(parts, flagToken+"="+sampleValueAlt(c.Path, f.Name, f.Type))
			}
		default:
			parts = append(parts, flagToken+"="+sampleValue(c.Path, f.Name, f.Type))
		}
	}

	if c.ArgsUsage != "" {
		for _, arg := range sampleArgs(c.ArgsUsage) {
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " ")
}

func sampleArgs(argsUsage string) []string {
	toks := strings.Fields(argsUsage)
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		if !(strings.Contains(t, "<") || strings.Contains(t, "[")) {
			continue
		}
		l := strings.Trim(t, "<>[]")
		l = strings.TrimSpace(strings.TrimSuffix(l, "..."))
		l = strings.ToLower(l)
		switch {
		case strings.Contains(l, "id"):
			out = append(out, "demo-id")
		case strings.Contains(l, "file"), strings.Contains(l, "path"), strings.Contains(l, "input"):
			out = append(out, "/tmp/input.json")
		case strings.Contains(l, "output"):
			out = append(out, "/tmp/output.json")
		case strings.Contains(l, "name"):
			out = append(out, "demo")
		default:
			out = append(out, "demo")
		}
	}
	return out
}

func sampleValue(path, flagName, flagType string) string {
	n := strings.ToLower(flagName)
	switch {
	case n == "email":
		return "admin@example.com"
	case n == "password":
		return "ChangeMe123!"
	case n == "username":
		return "admin"
	case strings.Contains(n, "token"):
		return "sample-token"
	case n == "name":
		if strings.Contains(path, "secret ") || strings.HasSuffix(path, " secret") {
			return "ENCRYPTED_SECRET"
		}
		return "demo-name"
	case strings.Contains(n, "id"):
		return "demo-id"
	case n == "command":
		return "go"
	case n == "secret":
		return "ENCRYPTED_SECRET:ENCRYPTED_SECRET"
	case n == "prefix":
		return "processgate/"
	case n == "env":
		return "general"
	case n == "env-prefix":
		return "APP"
	case n == "output" || n == "out":
		return "/tmp/output.json"
	case n == "input":
		return "/tmp/input.json"
	case strings.Contains(n, "file"):
		return "/tmp/input.json"
	case strings.Contains(n, "path"):
		return "/tmp/path"
	case n == "addr":
		return ":9090"
	case n == "cron":
		return "0 2 * * *"
	case n == "branch":
		return "main"
	case n == "provider":
		return "github"
	case n == "repo":
		return "owner/repo"
	case n == "severity":
		return "high"
	case n == "period":
		return "24h"
	case n == "limit":
		return "20"
	}

	switch flagType {
	case "int":
		return "1"
	case "duration":
		return "24h"
	case "float64":
		return "1.0"
	case "string[]":
		return "item1"
	default:
		return "demo"
	}
}

func sampleValueAlt(path, flagName, flagType string) string {
	n := strings.ToLower(flagName)
	switch {
	case n == "secret":
		return "DB_PASSWORD:DB_PASSWORD"
	case n == "scopes":
		return "secret:read"
	case n == "names":
		return "SECRET_TWO"
	case n == "param":
		return "user_id=u-123"
	}
	if flagType == "string[]" {
		return "item2"
	}
	_ = path
	return sampleValue(path, flagName, flagType)
}

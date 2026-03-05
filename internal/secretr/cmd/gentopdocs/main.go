package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/authz"
	apppkg "github.com/oarkflow/velocity/internal/secretr/cli/app"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

type cmdInfo struct {
	Path      string
	Usage     string
	ArgsUsage string
	Flags     []flagInfo
	Spec      authz.CommandAuthSpec
}

type flagInfo struct {
	Name     string
	Aliases  []string
	Type     string
	Required bool
	Usage    string
}

func main() {
	root := apppkg.BuildCLIRootForAuthz()
	specs := authz.BuildCLIAuthSpecs(root, nil)
	cmds := collect(root, "", specs)
	grouped := map[string][]cmdInfo{}
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
		sort.Slice(grouped[g], func(i, j int) bool { return grouped[g][i].Path < grouped[g][j].Path })
		file := groupDocFile(g)
		if shouldSkip(file) {
			continue
		}
		if err := os.WriteFile(file, []byte(renderGroupDoc(g, grouped[g])), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", file, err)
			os.Exit(1)
		}
		fmt.Println(file)
	}
}

func shouldSkip(path string) bool {
	base := filepath.Base(path)
	return base == "AUDIT.md" || base == "ENVELOPE.md"
}

func groupDocFile(group string) string {
	name := strings.ToUpper(strings.ReplaceAll(group, "-", "_"))
	return filepath.Join("internal", "secretr", name+".md")
}

func collect(cmd *cli.Command, prefix string, specs map[string]authz.CommandAuthSpec) []cmdInfo {
	if cmd == nil {
		return nil
	}
	out := make([]cmdInfo, 0)
	for _, sub := range cmd.Commands {
		if sub == nil {
			continue
		}
		name := strings.TrimSpace(sub.Name)
		if name == "" || name == "help" || name == "h" {
			continue
		}
		path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
		ci := cmdInfo{
			Path:      path,
			Usage:     strings.TrimSpace(sub.Usage),
			ArgsUsage: strings.TrimSpace(sub.ArgsUsage),
			Flags:     collectFlags(sub.Flags),
			Spec:      specs[path],
		}
		out = append(out, ci)
		out = append(out, collect(sub, path, specs)...)
	}
	return out
}

func collectFlags(flags []cli.Flag) []flagInfo {
	out := make([]flagInfo, 0, len(flags))
	for _, f := range flags {
		if f == nil {
			continue
		}
		names := f.Names()
		if len(names) == 0 {
			continue
		}
		fi := flagInfo{Name: names[0], Aliases: names[1:], Type: "string", Usage: strings.TrimSpace(f.String())}
		switch v := f.(type) {
		case *cli.StringFlag:
			fi.Type = "string"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		case *cli.StringSliceFlag:
			fi.Type = "string[]"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		case *cli.IntFlag:
			fi.Type = "int"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		case *cli.BoolFlag:
			fi.Type = "bool"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		case *cli.DurationFlag:
			fi.Type = "duration"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		case *cli.Float64Flag:
			fi.Type = "float64"
			fi.Required = v.Required
			fi.Usage = strings.TrimSpace(v.Usage)
		}
		out = append(out, fi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func renderGroupDoc(group string, cmds []cmdInfo) string {
	var b bytes.Buffer
	title := strings.ToUpper(group)
	b.WriteString("# " + title + " Command Deep-Dive\n\n")
	b.WriteString("This document is implementation-oriented guidance for the `secretr " + group + "` command group.\n\n")
	b.WriteString("It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.\n\n")

	b.WriteString("## 1. Command Surface\n\n")
	b.WriteString("| Subcommand | Purpose |\n")
	b.WriteString("|---|---|\n")
	for _, c := range cmds {
		u := dashIfEmpty(c.Usage)
		b.WriteString(fmt.Sprintf("| `secretr %s` | %s |\n", c.Path, escapePipe(u)))
	}
	b.WriteString("\n")

	b.WriteString("## 2. RBAC + Entitlement Scope Requirements\n\n")
	b.WriteString("Entitlement scope slugs are expected to match RBAC scope literals exactly.\n\n")
	b.WriteString("| Subcommand | Required Scopes |\n")
	b.WriteString("|---|---|\n")
	for _, c := range cmds {
		b.WriteString(fmt.Sprintf("| `secretr %s` | %s |\n", c.Path, scopesString(c.Spec.RequiredScopes)))
	}
	b.WriteString("\n")

	b.WriteString("## 3. ACL / Resource Model\n\n")
	b.WriteString("| Subcommand | Resource Type | ACL Required |\n")
	b.WriteString("|---|---|---|\n")
	for _, c := range cmds {
		rt := dashIfEmpty(c.Spec.ResourceType)
		acl := "no"
		if c.Spec.RequireACL {
			acl = "yes"
		}
		b.WriteString(fmt.Sprintf("| `secretr %s` | `%s` | %s |\n", c.Path, rt, acl))
	}
	b.WriteString("\n")

	b.WriteString("## 4. Flags and Positional Arguments\n\n")
	for _, c := range cmds {
		b.WriteString("### `secretr " + c.Path + "`\n\n")
		b.WriteString("Flags:\n\n")
		if len(c.Flags) == 0 {
			b.WriteString("- none\n\n")
		} else {
			b.WriteString("| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |\n")
			b.WriteString("|---|---|---|---|---|---|---|\n")
			for _, f := range c.Flags {
				aliases := "-"
				if len(f.Aliases) > 0 {
					parts := make([]string, 0, len(f.Aliases))
					for _, a := range f.Aliases {
						parts = append(parts, "`-"+a+"`")
					}
					aliases = strings.Join(parts, ", ")
				}
				req := "no"
				if f.Required {
					req = "yes"
				}
				fSpec, ok := c.Spec.Flags[f.Name]
				class := "-"
				acl := "-"
				if ok {
					class = "`" + string(fSpec.Class) + "`"
					if fSpec.RequireACL {
						acl = "yes"
					} else {
						acl = "no"
					}
				}
				b.WriteString(fmt.Sprintf("| `--%s` | %s | `%s` | %s | %s | %s | %s |\n",
					f.Name,
					aliases,
					f.Type,
					req,
					class,
					acl,
					escapePipe(dashIfEmpty(f.Usage)),
				))
			}
			b.WriteString("\n")
		}

		reqArgs, optArgs := parseArgs(c.ArgsUsage)
		b.WriteString("Positional arguments:\n\n")
		b.WriteString("| Required Positional Args | Optional Positional Args | ArgsUsage Source |\n")
		b.WriteString("|---|---|---|\n")
		b.WriteString(fmt.Sprintf("| %s | %s | `%s` |\n\n", joinCodeOrDash(reqArgs), joinCodeOrDash(optArgs), dashIfEmpty(c.ArgsUsage)))
	}

	b.WriteString("## 5. Copy-Paste Examples\n\n")
	for _, c := range cmds {
		b.WriteString("### `secretr " + c.Path + "`\n\n")
		b.WriteString("```bash\n")
		b.WriteString(exampleFor(c, false) + "\n")
		b.WriteString("```\n\n")
	}

	b.WriteString("## 6. Audit and Observability\n\n")
	b.WriteString("All commands in this group are currently observable through:\n")
	b.WriteString("- CLI command audit events (`type=cli`, `action=command_execute`)\n")
	b.WriteString("- centralized authz decision events (`type=authz`)\n")
	b.WriteString("- API request audit events when equivalent API routes are used (`type=api`, `action=request`)\n")
	b.WriteString("\n")
	b.WriteString("Command-specific domain events may also be emitted by the underlying managers. Validate this explicitly during parity testing.\n\n")

	b.WriteString("## 7. Review Checklist (Implementation + Security)\n\n")
	b.WriteString("Use this checklist to identify missing implementation pieces and hardening work:\n\n")
	b.WriteString("1. Verify every subcommand has expected domain-level audit events (not only CLI/authz wrappers).\n")
	b.WriteString("2. Validate flag-level ACL behavior for resource-selector flags (especially `--id`, `--name`, `--path`, `--resource`).\n")
	b.WriteString("3. Confirm positional arguments are explicitly modeled where needed (avoid implicit wildcard behavior).\n")
	b.WriteString("4. Confirm entitlement scope coverage for all subcommands and critical flags.\n")
	b.WriteString("5. Add API parity routes/tests for this group if missing.\n")
	b.WriteString("6. Ensure sensitive outputs are masked by default and require explicit reveal flags.\n")
	b.WriteString("7. Ensure destructive operations are audited with before/after context and denial reasons.\n")

	return b.String()
}

func scopesString(scopes []types.Scope) string {
	if len(scopes) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(scopes))
	for _, s := range scopes {
		parts = append(parts, "`"+string(s)+"`")
	}
	return strings.Join(parts, ", ")
}

func parseArgs(argsUsage string) (required []string, optional []string) {
	argsUsage = strings.TrimSpace(argsUsage)
	if argsUsage == "" {
		return nil, nil
	}
	toks := strings.Fields(argsUsage)
	for _, t := range toks {
		t = strings.Trim(t, ",;")
		if strings.HasPrefix(t, "<") && strings.Contains(t, ">") {
			n := strings.Trim(t, "<>")
			n = strings.TrimSuffix(n, "...")
			if n != "" {
				required = append(required, n)
			}
		} else if strings.HasPrefix(t, "[") && strings.Contains(t, "]") {
			n := strings.Trim(t, "[]")
			n = strings.TrimSuffix(n, "...")
			if n != "" {
				optional = append(optional, n)
			}
		}
	}
	required = uniq(required)
	optional = uniq(optional)
	return required, optional
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func joinCodeOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(v))
	for _, s := range v {
		parts = append(parts, "`"+s+"`")
	}
	return strings.Join(parts, ", ")
}

func escapePipe(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func exampleFor(c cmdInfo, includeOptional bool) string {
	parts := []string{"secretr", c.Path}
	for _, f := range c.Flags {
		if !f.Required && !includeOptional {
			continue
		}
		if !f.Required && includeOptional && f.Type == "bool" {
			continue
		}
		flagToken := "--" + f.Name
		switch f.Type {
		case "bool":
			parts = append(parts, flagToken)
		case "string[]":
			parts = append(parts, flagToken+"="+sampleValue(c.Path, f.Name, f.Type))
			if includeOptional {
				parts = append(parts, flagToken+"="+sampleValueAlt(c.Path, f.Name, f.Type))
			}
		default:
			parts = append(parts, flagToken+"="+sampleValue(c.Path, f.Name, f.Type))
		}
	}
	reqArgs, _ := parseArgs(c.ArgsUsage)
	for _, arg := range reqArgs {
		parts = append(parts, sampleArg(arg))
	}
	return strings.Join(parts, " ")
}

func sampleArg(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "id"):
		return "demo-id"
	case strings.Contains(n, "file"), strings.Contains(n, "path"), strings.Contains(n, "input"):
		return "/tmp/input.json"
	case strings.Contains(n, "output"):
		return "/tmp/output.json"
	case strings.Contains(n, "name"):
		return "demo"
	default:
		return "demo"
	}
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

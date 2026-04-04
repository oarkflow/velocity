package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/oarkflow/velocity"
	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/exec"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Exec Commands

func ExecRun(ctx context.Context, cmd *cli.Command) error {
	command := strings.TrimSpace(cmd.String("command"))
	// args := cmd.StringSlice("arg") // cli v3 uses Args()
	args := cmd.Args().Slice()
	if command == "" {
		if len(args) == 0 {
			return fmt.Errorf("usage: exec [flags] <command> [args...]")
		}
		command = args[0]
		args = args[1:]
	}

	secretMappings := cmd.StringSlice("secret") // format: SECRET_ID:ENV_VAR or SECRET_ID:FILE_PATH:file
	loadAll := cmd.Bool("all-secrets")
	prefix := strings.TrimSpace(cmd.String("prefix"))
	envFilter := strings.TrimSpace(firstNonEmpty(
		cmd.String("env"),
		cmd.String("ns"),
		cmd.String("namespace"),
		cmd.String("group"),
		cmd.String("tenant"),
	))
	envPrefix := strings.TrimSpace(cmd.String("env-prefix"))
	stripPrefix := prefix
	if stripPrefix == "" && envFilter != "" {
		stripPrefix = envFilter
	}
	isolation := cmd.String("isolation")
	seccompProfile := cmd.String("seccomp-profile")
	strictSandbox := cmd.Bool("strict-sandbox")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	var bindings []exec.SecretBinding
	for _, mapping := range secretMappings {
		parts := strings.Split(mapping, ":")
		if len(parts) >= 2 {
			id := types.ID(parts[0])
			target := parts[1]
			type_ := "env"
			if len(parts) > 2 && parts[2] == "file" {
				type_ = "file"
			}
			bindings = append(bindings, exec.SecretBinding{
				SecretID:   id,
				TargetType: type_,
				TargetName: target,
			})
			continue
		}
		return fmt.Errorf("invalid --secret mapping %q, expected SECRET_ID:ENV_VAR or SECRET_ID:FILE_PATH:file", mapping)
	}

	// Default behavior for `secretr exec`: when no explicit mapping/prefix is
	// provided, load secrets from the default "general" category/environment.
	if len(bindings) == 0 && !loadAll && prefix == "" {
		loadAll = true
		if envFilter == "" {
			envFilter = "general"
			stripPrefix = "general"
		} else {
			stripPrefix = envFilter
		}
	}

	// Use transient executor
	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}

	executor := exec.NewExecutor(exec.ExecutorConfig{
		AuditEngine: c.Audit,
		SecretRetriever: func(ctx context.Context, id types.ID) (string, error) {
			if v, found, err := getVelocitySecretValue(string(id)); err != nil {
				return "", err
			} else if found {
				return v, nil
			}
			val, err := c.Secrets.Get(ctx, string(id), c.CurrentIdentityID(), mfaVerified)
			if err != nil {
				return "", err
			}
			return string(val), nil
		},
		Isolation:      exec.IsolationLevel(isolation),
		SeccompProfile: seccompProfile,
		StrictSandbox:  strictSandbox,
	})
	defer executor.Close()

	customEnv := map[string]string{}
	if loadAll || prefix != "" {
		loaded, err := loadBulkSecretsFromVelocity(prefix, envFilter)
		if err != nil {
			return err
		}
		if len(loaded) == 0 {
			listOpts := secrets.ListSecretsOptions{
				Prefix:      prefix,
				Environment: envFilter,
			}
			secretItems, err := c.Secrets.List(ctx, listOpts)
			if err != nil {
				return err
			}
			for _, item := range secretItems {
				raw, err := c.Secrets.Get(ctx, item.Name, c.CurrentIdentityID(), mfaVerified)
				if err != nil {
					return fmt.Errorf("load secret %s: %w", item.Name, err)
				}
				loaded = append(loaded, namedSecret{Name: item.Name, Value: string(raw)})
			}
		}
		for _, item := range loaded {
			nameForEnv := secretNameForEnv(item.Name, stripPrefix)
			for k, v := range flattenSecretToEnv(nameForEnv, item.Value, envPrefix) {
				if prev, exists := customEnv[k]; exists && prev != v {
					return fmt.Errorf("environment variable collision on %s while loading prefix %q", k, prefix)
				}
				customEnv[k] = v
			}
		}
	}

	res, err := executor.Execute(ctx, exec.ExecuteOptions{
		Command:  command,
		Args:     args,
		Bindings: bindings,
		ActorID:  c.CurrentIdentityID(),
		Env:      customEnv,
	})
	if err != nil {
		return err
	}

	if !res.Success {
		return fmt.Errorf("command failed with exit code %d: %s (error: %s)", res.ExitCode, res.Stderr, res.Error)
	}

	fmt.Print(res.Stdout)
	if res.Stderr != "" {
		fmt.Fprint(os.Stderr, res.Stderr)
	}
	return nil
}

func flattenSecretToEnv(secretName, rawValue, envPrefix string) map[string]string {
	trimmed := strings.TrimSpace(rawValue)
	if trimmed == "" {
		return map[string]string{toEnvVarWithPrefix(secretName, envPrefix): ""}
	}

	var payload any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return map[string]string{toEnvVarWithPrefix(secretName, envPrefix): rawValue}
	}

	out := make(map[string]string)
	switch v := payload.(type) {
	case map[string]any:
		flattenJSON("", v, out, envPrefix)
	default:
		out[toEnvVarWithPrefix(secretName, envPrefix)] = stringifyJSONScalar(v)
	}
	return out
}

func flattenJSON(path string, value any, out map[string]string, envPrefix string) {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			next := appendPath(path, k)
			flattenJSON(next, child, out, envPrefix)
		}
	case []any:
		for i, child := range v {
			next := appendPath(path, strconv.Itoa(i))
			flattenJSON(next, child, out, envPrefix)
		}
	default:
		if path == "" {
			return
		}
		out[toEnvVarWithPrefix(path, envPrefix)] = stringifyJSONScalar(v)
	}
}

func appendPath(base, part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return base
	}
	if base == "" {
		return part
	}
	return base + "_" + part
}

func toEnvVarWithPrefix(name, envPrefix string) string {
	base := toEnvVar(name)
	prefix := normalizeEnvToken(envPrefix)
	if prefix == "" {
		return base
	}
	if base == "" {
		return prefix
	}
	return prefix + "_" + base
}

func normalizeEnvToken(s string) string {
	up := strings.ToUpper(strings.TrimSpace(s))
	up = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			return r
		default:
			return '_'
		}
	}, up)
	up = strings.Trim(up, "_")
	for strings.Contains(up, "__") {
		up = strings.ReplaceAll(up, "__", "_")
	}
	return up
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func stringifyJSONScalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

type namedSecret struct {
	Name  string
	Value string
}

func loadBulkSecretsFromVelocity(prefix, category string) ([]namedSecret, error) {
	adapter := client.GetGlobalAdapter()
	if adapter == nil || adapter.GetVelocityDB() == nil {
		return nil, nil
	}
	return listVelocitySecrets(adapter.GetVelocityDB(), prefix, category)
}

func listVelocitySecrets(db *velocity.DB, prefix, category string) ([]namedSecret, error) {
	if db == nil {
		return nil, nil
	}
	keys, _ := db.KeysPage(0, 10000)
	out := make([]namedSecret, 0)
	for _, key := range keys {
		rawKey := string(key)
		cat, name, ok := parseVelocitySecretKey(rawKey)
		if !ok {
			continue
		}
		if category != "" && cat != category {
			continue
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		val, err := db.Get(key)
		if err != nil {
			continue
		}
		out = append(out, namedSecret{
			Name:  cat + ":" + name,
			Value: string(val),
		})
	}
	return out, nil
}

func parseVelocitySecretKey(key string) (category, name string, ok bool) {
	const pfx = "secret:"
	if !strings.HasPrefix(key, pfx) {
		return "", "", false
	}
	rest := strings.TrimPrefix(key, pfx)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	category = strings.TrimSpace(parts[0])
	name = strings.TrimSpace(parts[1])
	if category == "" || name == "" {
		return "", "", false
	}
	return category, name, true
}

func getVelocitySecretValue(name string) (string, bool, error) {
	return client.LookupVelocitySecretValue(name)
}

func secretNameForEnv(secretName, prefix string) string {
	name := strings.TrimSpace(secretName)
	pfx := strings.TrimSpace(prefix)
	if pfx == "" {
		return name
	}

	candidates := []string{pfx}
	if !strings.HasSuffix(pfx, ":") {
		candidates = append(candidates, pfx+":")
	}
	if !strings.HasSuffix(pfx, "/") {
		candidates = append(candidates, pfx+"/")
	}
	for _, c := range candidates {
		if strings.HasPrefix(name, c) {
			rest := strings.TrimPrefix(name, c)
			rest = strings.TrimLeft(rest, ":/_")
			if strings.TrimSpace(rest) != "" {
				return rest
			}
		}
	}
	return name
}

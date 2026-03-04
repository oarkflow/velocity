package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Env outputs a shell export command for a single secret
func Env(ctx context.Context, cmd *cli.Command) error {
	key := cmd.Args().First()
	if key == "" {
		return fmt.Errorf("usage: env <key>")
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretRead); err != nil {
		return err
	}

	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}

	val, err := c.Secrets.Get(ctx, key, c.CurrentIdentityID(), mfaVerified)
	if err != nil {
		return err
	}

	envVar := toEnvVar(key)
	fmt.Printf("export %s='%s'\n", envVar, escapeValue(string(val)))
	return nil
}

// LoadEnv outputs shell export commands for all secrets
func LoadEnv(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretList); err != nil {
		return err
	}

	// List all secrets
	opts := secrets.ListSecretsOptions{}
	secretsList, err := c.Secrets.List(ctx, opts)
	if err != nil {
		return err
	}

	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}

	for _, s := range secretsList {
		val, err := c.Secrets.Get(ctx, s.Name, c.CurrentIdentityID(), mfaVerified)
		if err != nil {
			continue
		}
		envVar := toEnvVar(s.Name)
		fmt.Printf("export %s='%s'\n", envVar, escapeValue(string(val)))
	}
	return nil
}

// Enrich runs a command with secrets injected as environment variables
func Enrich(ctx context.Context, cmd *cli.Command) error {
	command := cmd.Args().First()
	if command == "" {
		return fmt.Errorf("usage: enrich <command> [args...]")
	}
	args := cmd.Args().Slice()[1:]

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Build env map
	opts := secrets.ListSecretsOptions{}
	secretsList, err := c.Secrets.List(ctx, opts)
	if err != nil {
		return err
	}

	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}

	env := os.Environ()
	for _, s := range secretsList {
		val, err := c.Secrets.Get(ctx, s.Name, c.CurrentIdentityID(), mfaVerified)
		if err != nil {
			continue
		}
		envVar := toEnvVar(s.Name)
		env = append(env, fmt.Sprintf("%s=%s", envVar, string(val)))
	}

	// Run command
	runCmd := exec.CommandContext(ctx, command, args...)
	runCmd.Env = env
	runCmd.Stdin = os.Stdin
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	return runCmd.Run()
}

func toEnvVar(name string) string {
	s := strings.ReplaceAll(name, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return strings.ToUpper(s)
}

func escapeValue(val string) string {
	return strings.ReplaceAll(val, "'", "'\\''")
}

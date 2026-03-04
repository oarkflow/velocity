package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/exec"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Exec Commands

func ExecRun(ctx context.Context, cmd *cli.Command) error {
	command := cmd.String("command")
	// args := cmd.StringSlice("arg") // cli v3 uses Args()
	args := cmd.Args().Slice()

	secretMappings := cmd.StringSlice("secret") // format: SECRET_ID:ENV_VAR or SECRET_ID:FILE_PATH:file
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

	res, err := executor.ExecuteWithSecrets(ctx, command, args, bindings, c.CurrentIdentityID())
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

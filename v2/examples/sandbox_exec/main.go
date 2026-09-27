// Command sandbox_exec demonstrates Velocity v2's secure sandboxed command
// execution (api.SandboxService, plugins/sandbox): no shell interpretation,
// an enforced command allowlist, explicit-only environment, and injecting
// secrets from SecretService as env vars without ever printing them.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/sandbox"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-sandbox-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "01234567890123456789012345678901"}},
		{Name: "secret", Enabled: true},
		{Name: "sandbox", Enabled: true, Config: map[string]any{
			"allowed_commands": []any{"/bin/echo", "/usr/bin/env"},
		}},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		secret.NewPlugin("storage-lsm", "crypto-xchacha"),
		sandbox.NewPlugin(),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	secretSvc := k.Registry().MustLookup("secret").(api.SecretService)
	sb := k.Registry().MustLookup("sandbox").(api.SandboxService)

	fmt.Println("=== Run an allowlisted command ===")
	res, err := sb.Run(ctx, "/bin/echo", []string{"hello from the sandbox"}, api.SandboxOptions{Timeout: 5 * time.Second})
	must(err)
	fmt.Printf("stdout: %q\n", strings.TrimSpace(string(res.Stdout)))
	fmt.Printf("sandbox mode actually used: %s\n", res.Mode)

	fmt.Println("\n=== Attempt a command NOT on the allowlist ===")
	marker := filepath.Join(dir, "should-not-be-deleted")
	must(os.WriteFile(marker, []byte("still here"), 0o600))
	_, err = sb.Run(ctx, "/bin/rm", []string{"-f", marker}, api.SandboxOptions{Timeout: 5 * time.Second})
	fmt.Printf("Run(\"/bin/rm\") err: %v\n", err)
	if _, statErr := os.Stat(marker); statErr == nil {
		fmt.Println("marker file survived (correct: disallowed command never ran)")
	} else {
		fmt.Println("SECURITY FAILURE: marker file was deleted")
	}

	fmt.Println("\n=== Inject a secret as an env var, without ever printing its value ===")
	_, err = secretSvc.Set(ctx, "db_password", []byte("hunter2-super-secret"))
	must(err)
	res, err = sb.RunWithSecrets(ctx, secretSvc, []string{"db_password"}, "/usr/bin/env", nil, api.SandboxOptions{Timeout: 5 * time.Second})
	must(err)
	// Prove injection happened by checking the KEY is present in the
	// child's environment dump — never print res.Stdout itself, which
	// would contain the raw secret value.
	injected := strings.Contains(string(res.Stdout), "DB_PASSWORD=")
	fmt.Printf("secret injected as DB_PASSWORD: %v\n", injected)
	fmt.Printf("(the actual secret value is intentionally never printed by this example)\n")

	fmt.Println("\ndone.")
}

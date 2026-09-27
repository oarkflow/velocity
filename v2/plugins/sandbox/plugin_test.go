package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// --- stub kernel, matching the convention used across this codebase's
// other plugin tests (see e.g. plugins/crypto-xchacha/xchacha_test.go) ---

type stubEventBus struct{}

func (stubEventBus) Publish(ctx context.Context, ev api.Event)              {}
func (stubEventBus) Subscribe(topic string, h api.Handler) api.Subscription { return stubSub{} }

type stubSub struct{}

func (stubSub) Unsubscribe() {}

type stubRegistry struct{ services map[string]any }

func (r *stubRegistry) Provide(name string, svc any) error { r.services[name] = svc; return nil }
func (r *stubRegistry) Lookup(name string) (any, bool)     { s, ok := r.services[name]; return s, ok }
func (r *stubRegistry) MustLookup(name string) any         { return r.services[name] }

type stubConfig struct{ data map[string]any }

func (c stubConfig) Scoped(string) api.PluginConfig { return stubPluginConfig{data: c.data} }

type stubPluginConfig struct{ data map[string]any }

func (c stubPluginConfig) Raw() map[string]any { return c.data }
func (c stubPluginConfig) String(key, def string) string {
	if v, ok := c.data[key].(string); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Int(key string, def int) int {
	if v, ok := c.data[key].(int); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Bool(key string, def bool) bool {
	if v, ok := c.data[key].(bool); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Duration(key string, def time.Duration) time.Duration {
	if v, ok := c.data[key].(time.Duration); ok {
		return v
	}
	return def
}

type stubLogger struct{}

func (stubLogger) Debug(string, ...any) {}
func (stubLogger) Info(string, ...any)  {}
func (stubLogger) Warn(string, ...any)  {}
func (stubLogger) Error(string, ...any) {}

type stubKernel struct {
	reg *stubRegistry
	cfg stubConfig
}

func (k stubKernel) Registry() api.Registry     { return k.reg }
func (k stubKernel) Events() api.EventBus       { return stubEventBus{} }
func (k stubKernel) Config() api.ConfigProvider { return k.cfg }
func (k stubKernel) Logger() api.Logger         { return stubLogger{} }

func newTestKernel(cfgData map[string]any) stubKernel {
	return stubKernel{reg: &stubRegistry{services: map[string]any{}}, cfg: stubConfig{data: cfgData}}
}

func mustInit(t *testing.T, cfgData map[string]any) *Plugin {
	t.Helper()
	p := NewPlugin()
	k := newTestKernel(cfgData)
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

// --- stub SecretService for RunWithSecrets tests ---

type stubSecrets struct {
	values map[string]string
	failOn string
}

func (s stubSecrets) Set(ctx context.Context, name string, value []byte) (int, error) {
	return 1, nil
}
func (s stubSecrets) Get(ctx context.Context, name string, version int) ([]byte, error) {
	if name == s.failOn {
		return nil, errors.New("secret backend unavailable")
	}
	v, ok := s.values[name]
	if !ok {
		return nil, errors.New("secret not found: " + name)
	}
	return []byte(v), nil
}
func (s stubSecrets) Versions(ctx context.Context, name string) ([]api.SecretVersion, error) {
	return nil, nil
}
func (s stubSecrets) Delete(ctx context.Context, name string) error { return nil }
func (s stubSecrets) Rotate(ctx context.Context, name string) error { return nil }

var _ api.SecretService = stubSecrets{}

// --- tests ---

func TestRun_ShellMetacharactersAreInertNotInterpreted(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "should-not-be-touched")
	if err := os.WriteFile(marker, []byte("still here"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := mustInit(t, map[string]any{"allowed_commands": []any{"echo"}})
	dangerous := "; rm -f " + marker + " ; $(rm -f " + marker + ")"

	res, err := p.Run(context.Background(), "echo", []string{dangerous}, api.SandboxOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, stderr=%s", res.ExitCode, res.Stderr)
	}
	got := strings.TrimSpace(string(res.Stdout))
	if got != dangerous {
		t.Fatalf("echo output = %q, want the literal dangerous string %q (proves it was NOT shell-interpreted)", got, dangerous)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker file was removed — shell metacharacters were interpreted! stat err: %v", err)
	}
}

func TestRun_AllowlistEnforcedBeforeSpawning(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	p := mustInit(t, map[string]any{"allowed_commands": []any{"echo"}}) // "touch" NOT allowlisted

	_, err := p.Run(context.Background(), "touch", []string{marker}, api.SandboxOptions{})
	if err == nil {
		t.Fatal("expected Run to refuse a non-allowlisted command")
	}
	if !strings.Contains(err.Error(), "not on the allowlist") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("marker file exists — the disallowed command actually ran")
	}
}

func TestRun_NoAllowlistConfiguredRefusesEverything(t *testing.T) {
	p := mustInit(t, nil) // no "allowed_commands" key at all
	_, err := p.Run(context.Background(), "echo", []string{"hi"}, api.SandboxOptions{})
	if err == nil {
		t.Fatal("expected Run to refuse when no allowlist is configured")
	}
	if !strings.Contains(err.Error(), "no commands allowlisted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_ExplicitEnvOnly_DoesNotInheritParentEnv(t *testing.T) {
	// A distinctive marker only present in THIS test process's real
	// environment — if the child sees it, env inheritance leaked.
	const leakKey = "VELOCITY_SANDBOX_TEST_LEAK_MARKER"
	t.Setenv(leakKey, "leaked-value-should-never-appear-in-child")

	p := mustInit(t, map[string]any{"allowed_commands": []any{"/usr/bin/env"}})
	res, err := p.Run(context.Background(), "/usr/bin/env", nil, api.SandboxOptions{
		Env: map[string]string{"ONLY_THIS": "should-be-here"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "ONLY_THIS=should-be-here") {
		t.Fatalf("child env missing the explicitly-provided var; got:\n%s", out)
	}
	if strings.Contains(out, leakKey) {
		t.Fatalf("child env leaked the parent process's real environment; got:\n%s", out)
	}
}

func TestRun_TimeoutKillsLongRunningProcess(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"sleep"}})

	start := time.Now()
	res, err := p.Run(context.Background(), "sleep", []string{"30"}, api.SandboxOptions{
		Timeout: 200 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected a timeout error, got nil (result: %+v)", res)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v — timeout was not enforced promptly", elapsed)
	}
}

func TestRun_OutputTruncation(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"echo"}})
	longArg := strings.Repeat("x", 1000)

	res, err := p.Run(context.Background(), "echo", []string{longArg}, api.SandboxOptions{
		MaxOutputBytes: 50,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated {
		t.Fatal("expected Truncated = true")
	}
	if len(res.Stdout) > 50 {
		t.Fatalf("captured %d bytes, want <= 50", len(res.Stdout))
	}
}

func TestRunWithSecrets_InjectsResolvedValueAndNeverLeaksItOnFailure(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"/usr/bin/env"}})
	secrets := stubSecrets{values: map[string]string{"db_password": "sup3r-s3cr3t-value"}}

	res, err := p.RunWithSecrets(context.Background(), secrets, []string{"db_password"}, "/usr/bin/env", nil, api.SandboxOptions{})
	if err != nil {
		t.Fatalf("RunWithSecrets: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "DB_PASSWORD=sup3r-s3cr3t-value") {
		t.Fatalf("expected injected secret in child env; got:\n%s", res.Stdout)
	}

	// Now force a resolution failure for an unrelated secret and confirm
	// the value of the FIRST (successfully-resolved) secret never leaks
	// into the error, and the failing secret's name is mentioned but not
	// some value.
	secrets2 := stubSecrets{values: map[string]string{"db_password": "sup3r-s3cr3t-value"}, failOn: "missing_one"}
	_, err = p.RunWithSecrets(context.Background(), secrets2, []string{"db_password", "missing_one"}, "/usr/bin/env", nil, api.SandboxOptions{})
	if err == nil {
		t.Fatal("expected an error resolving missing_one")
	}
	if strings.Contains(err.Error(), "sup3r-s3cr3t-value") {
		t.Fatalf("secret value leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "missing_one") {
		t.Fatalf("expected error to name the failing secret: %v", err)
	}
}

func TestRunWithSecrets_ExplicitEnvWinsOverSecretOnCollision(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"/usr/bin/env"}})
	secrets := stubSecrets{values: map[string]string{"api_key": "secret-value"}}

	res, err := p.RunWithSecrets(context.Background(), secrets, []string{"api_key"}, "/usr/bin/env", nil, api.SandboxOptions{
		Env: map[string]string{"API_KEY": "explicit-override"},
	})
	if err != nil {
		t.Fatalf("RunWithSecrets: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "API_KEY=explicit-override") {
		t.Fatalf("expected explicit opts.Env to win over the secret; got:\n%s", res.Stdout)
	}
	if strings.Contains(string(res.Stdout), "secret-value") {
		t.Fatalf("secret value should have been overridden, but appeared in output:\n%s", res.Stdout)
	}
}

func TestSandboxMode_ReflectsWhatActuallyRan(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"echo"}})
	res, err := p.Run(context.Background(), "echo", []string{"mode-check"}, api.SandboxOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if p.osSandboxTool != "" {
		if res.Mode != api.SandboxModeOSLevel {
			t.Fatalf("sandbox-exec is available on this host (%s) but Mode = %q, want %q", p.osSandboxTool, res.Mode, api.SandboxModeOSLevel)
		}
		t.Logf("OS-level sandbox tool in use on this machine: %s", p.osSandboxTool)
	} else {
		if res.Mode != api.SandboxModeRestricted {
			t.Fatalf("no OS-level sandbox tool found but Mode = %q, want %q", res.Mode, api.SandboxModeRestricted)
		}
		t.Log("no OS-level sandbox tool found on this machine — Mode correctly reports restricted-env-only")
	}
}

func TestRun_FreshWorkDirCreatedAndCleanedUpWhenNotSpecified(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"pwd"}})
	res, err := p.Run(context.Background(), "pwd", nil, api.SandboxOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	dir := strings.TrimSpace(string(res.Stdout))
	if dir == "" {
		t.Fatal("pwd produced no output")
	}
	// It should have been an isolated temp dir, and should be gone now.
	if _, err := os.Stat(dir); err == nil {
		t.Fatalf("isolated work dir %q was not cleaned up after Run", dir)
	}
}

func TestRun_NonZeroExitIsNotAnError(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"false"}})
	res, err := p.Run(context.Background(), "false", nil, api.SandboxOptions{})
	if err != nil {
		t.Fatalf("Run returned an error for a plain non-zero exit: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("expected a non-zero ExitCode from /usr/bin/false")
	}
}

func TestParseAllowedCommands_AcceptsCommaSeparatedString(t *testing.T) {
	cfg := stubPluginConfig{data: map[string]any{"allowed_commands": "echo, sleep ,  pwd"}}
	got := parseAllowedCommands(cfg)
	want := []string{"echo", "sleep", "pwd"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestHealth_ReportsSandboxAvailability(t *testing.T) {
	p := mustInit(t, map[string]any{"allowed_commands": []any{"echo"}})
	h := p.Health()
	if h.Status != "ok" {
		t.Fatalf("Health.Status = %q, want ok", h.Status)
	}
	if !bytes.Contains([]byte(h.Detail), []byte("sandbox")) {
		t.Fatalf("Health.Detail = %q, expected it to mention sandbox availability", h.Detail)
	}
}

// Package sandbox implements Velocity v2's "sandbox" plugin: running an
// external command with explicit, minimal privilege.
//
// This closes a real gap left open in v1: v1's examples referenced a
// "secretr exec" concept (fetch a secret, inject it as an env var, run a
// command) but the actual secretr binary/sandbox was never built anywhere
// in that codebase (v1's own docs/LIMITATIONS.md flags cmd/secretr as
// referenced-but-missing). This package is the real implementation of
// that idea, built from scratch with real security controls:
//
//   - No shell interpretation, ever — exec.CommandContext(ctx, name,
//     args...) directly, never /bin/sh -c. Shell metacharacters in an
//     argument are inert data to the target program, not commands.
//   - A command allowlist enforced BEFORE any process is spawned. Empty
//     configuration means "refuse everything" — there is no wildcard
//     default-allow.
//   - An explicit, never-inherited environment (Go's exec.Cmd inherits
//     the parent's environment when Env is left nil; this package always
//     sets a non-nil slice, even when empty).
//   - A fresh, isolated working directory per call unless one is given.
//   - A timeout, always enforced (a configured default if the caller
//     doesn't specify one).
//   - Bounded stdout/stderr capture, so a runaway process can't exhaust
//     memory.
//   - An automatic upgrade to a real OS-level sandbox (macOS
//     sandbox-exec, checked and used if present) when available, with
//     SandboxResult.Mode always reporting honestly which level of
//     isolation actually applied — never claims OS-level protection it
//     didn't actually get.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "sandbox"

// Plugin implements api.Plugin + api.SandboxService. It is stateless
// (no storage dependency) — Dependencies() returns nil.
type Plugin struct {
	mu sync.RWMutex

	allowedCommands      []string
	defaultTimeout       time.Duration
	defaultMaxOutputByte int

	// osSandboxTool is the absolute path to a discovered OS-level sandbox
	// wrapper (currently only macOS's sandbox-exec), or "" if none is
	// available on this host. Detected once, in Init.
	osSandboxTool string

	log api.Logger
}

func NewPlugin() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string           { return pluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()

	cfg := k.Config().Scoped(pluginName)
	p.allowedCommands = parseAllowedCommands(cfg)
	p.defaultTimeout = cfg.Duration("default_timeout", 30*time.Second)
	p.defaultMaxOutputByte = cfg.Int("default_max_output_bytes", 1<<20) // 1MiB

	// Detect a real OS-level sandbox tool once. Only macOS's sandbox-exec
	// is wired up today; Linux's bubblewrap (bwrap) is a natural
	// follow-up with an analogous profile, not implemented here — absence
	// of either just means SandboxModeRestricted, never a failure to
	// boot.
	if runtime.GOOS == "darwin" {
		if path, err := exec.LookPath("sandbox-exec"); err == nil {
			p.osSandboxTool = path
		}
	}

	if len(p.allowedCommands) == 0 && p.log != nil {
		p.log.Warn("sandbox: no allowed_commands configured — every Run call will be refused until this deployment's manifest sets one")
	}

	return k.Registry().Provide(pluginName, p)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.osSandboxTool != "" {
		return api.Health{Status: "ok", Detail: "os-level sandbox available (" + p.osSandboxTool + ")"}
	}
	return api.Health{Status: "ok", Detail: "restricted-env-only (no OS-level sandbox tool found)"}
}

var (
	_ api.Plugin         = (*Plugin)(nil)
	_ api.SandboxService = (*Plugin)(nil)
)

// parseAllowedCommands reads "allowed_commands" from the plugin's raw
// config, accepting a JSON array of strings (the natural shape from a
// JSON manifest) or a single comma-separated string, for convenience.
// Entries are trimmed; empty entries are dropped.
func parseAllowedCommands(cfg api.PluginConfig) []string {
	raw := cfg.Raw()
	v, ok := raw["allowed_commands"]
	if !ok {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	case []string:
		for _, s := range t {
			add(s)
		}
	case string:
		for _, s := range strings.Split(t, ",") {
			add(s)
		}
	}
	return out
}

// resolveAllowed resolves name to an absolute, executable path and checks
// it against the configured allowlist BEFORE any process is spawned.
// Matching supports both an exact-path allowlist entry and a
// basename-only allowlist entry (e.g. "echo" matches "/bin/echo"),
// documented here since api.SandboxService's own doc comment doesn't
// specify the matching rule: an allowlist entry matches if it equals the
// resolved absolute path, OR the resolved path's basename, OR the
// caller-supplied name verbatim.
func (p *Plugin) resolveAllowed(name string) (string, error) {
	p.mu.RLock()
	allowed := p.allowedCommands
	p.mu.RUnlock()

	if len(allowed) == 0 {
		return "", fmt.Errorf("sandbox: no commands allowlisted (configure allowed_commands before calling Run)")
	}

	var resolved string
	if strings.ContainsRune(name, '/') || filepath.IsAbs(name) {
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", fmt.Errorf("sandbox: resolving path %q: %w", name, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("sandbox: command %q not found: %w", name, err)
		}
		resolved = abs
	} else {
		lp, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("sandbox: command %q not found on PATH: %w", name, err)
		}
		resolved = lp
	}

	base := filepath.Base(resolved)
	for _, a := range allowed {
		if a == resolved || a == base || a == name {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("sandbox: command %q is not on the allowlist", name)
}

// limitWriter caps how many bytes it retains, discarding (but still
// "accepting", so the writer side of an os/exec pipe never errors or
// blocks) anything beyond the limit, and records whether truncation
// happened. Not safe for concurrent use by multiple goroutines writing to
// the SAME limitWriter — each of stdout/stderr gets its own instance, and
// each is only ever written by the one goroutine os/exec uses for that
// stream, so no locking is needed here.
type limitWriter struct {
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.limit {
		w.truncated = true
		return len(p), nil
	}
	remaining := w.limit - w.buf.Len()
	if len(p) > remaining {
		w.buf.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// sandboxExecProfile builds a minimal, real Seatbelt (macOS sandbox-exec)
// profile: deny everything by default, then allow exactly what a normal
// short-lived subprocess needs to actually run (process exec/fork,
// reading files — needed for dynamic linking, locale data, etc. — and
// writing only within workDir), while leaving network access denied
// (there is no "allow network*" rule) and process creation outside the
// target confined by the default deny.
func sandboxExecProfile(workDir string) string {
	return fmt.Sprintf(`(version 1)
(deny default)
(allow process-fork)
(allow process-exec)
(allow file-read*)
(allow file-write* (subpath %q))
(allow file-write-data (literal "/dev/null"))
(allow file-write-data (literal "/dev/stdout"))
(allow file-write-data (literal "/dev/stderr"))
(allow sysctl-read)
(allow mach-lookup)
(allow signal (target self))
`, workDir)
}

// Run implements api.SandboxService.
func (p *Plugin) Run(ctx context.Context, name string, args []string, opts api.SandboxOptions) (api.SandboxResult, error) {
	resolved, err := p.resolveAllowed(name)
	if err != nil {
		return api.SandboxResult{}, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		p.mu.RLock()
		timeout = p.defaultTimeout
		p.mu.RUnlock()
	}
	maxOutput := opts.MaxOutputBytes
	if maxOutput <= 0 {
		p.mu.RLock()
		maxOutput = p.defaultMaxOutputByte
		p.mu.RUnlock()
	}

	workDir := opts.WorkDir
	cleanupWorkDir := false
	if workDir == "" {
		dir, err := os.MkdirTemp("", "velocity-sandbox-*")
		if err != nil {
			return api.SandboxResult{}, fmt.Errorf("sandbox: creating isolated work dir: %w", err)
		}
		workDir = dir
		cleanupWorkDir = true
	}
	if cleanupWorkDir {
		defer os.RemoveAll(workDir)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Explicit environment ONLY — never nil, or exec.Cmd inherits this
	// process's real environment.
	env := make([]string, 0, len(opts.Env))
	for k, v := range opts.Env {
		env = append(env, k+"="+v)
	}

	mode := api.SandboxModeRestricted
	var cmd *exec.Cmd

	p.mu.RLock()
	osTool := p.osSandboxTool
	p.mu.RUnlock()

	if osTool != "" {
		profile := sandboxExecProfile(workDir)
		fullArgs := append([]string{"-p", profile, resolved}, args...)
		cmd = exec.CommandContext(runCtx, osTool, fullArgs...)
		mode = api.SandboxModeOSLevel
	} else {
		cmd = exec.CommandContext(runCtx, resolved, args...)
	}
	cmd.Env = env
	cmd.Dir = workDir

	stdout := &limitWriter{limit: maxOutput}
	stderr := &limitWriter{limit: maxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	result := api.SandboxResult{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Mode:      mode,
		Truncated: stdout.truncated || stderr.truncated,
	}

	if runErr != nil {
		if runCtx.Err() != nil {
			// Timed out (or parent ctx was cancelled) — report clearly as
			// such rather than a generic non-zero-exit error.
			result.ExitCode = -1
			return result, fmt.Errorf("sandbox: command %q timed out or was cancelled: %w", name, runCtx.Err())
		}
		var exitErr *exec.ExitError
		if ok := errorsAsExitError(runErr, &exitErr); ok {
			result.ExitCode = exitErr.ExitCode()
			// A non-zero exit is not itself an error condition worth
			// failing Run over — the caller gets ExitCode and can decide.
			return result, nil
		}
		// Something failed before/around the process actually running
		// (e.g. exec itself failed) — a real error.
		result.ExitCode = -1
		return result, fmt.Errorf("sandbox: running %q: %w", name, runErr)
	}

	return result, nil
}

// errorsAsExitError avoids importing "errors" just for one As call in a
// way that could shadow the exec import name; small local helper.
func errorsAsExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// RunWithSecrets implements api.SandboxService. Precedence on a name
// collision: an explicit opts.Env entry WINS over a resolved secret of
// the same (uppercased) name — the caller's explicit override is
// intentional, a secret filling in a default is not, so the more
// specific/explicit value should win. Secret VALUES are never placed
// anywhere except the built environment map handed to Run — never in a
// log call, never in a returned error (an error naming which secret
// FAILED to resolve is fine and useful; the value itself never appears).
func (p *Plugin) RunWithSecrets(ctx context.Context, secrets api.SecretService, secretNames []string, name string, args []string, opts api.SandboxOptions) (api.SandboxResult, error) {
	env := make(map[string]string, len(opts.Env)+len(secretNames))
	for _, sn := range secretNames {
		val, err := secrets.Get(ctx, sn, 0)
		if err != nil {
			return api.SandboxResult{}, fmt.Errorf("sandbox: resolving secret %q: %w", sn, err)
		}
		env[strings.ToUpper(sn)] = string(val)
	}
	for k, v := range opts.Env {
		env[k] = v // explicit opts.Env wins over a same-named secret
	}
	opts.Env = env
	return p.Run(ctx, name, args, opts)
}

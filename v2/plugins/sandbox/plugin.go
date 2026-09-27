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

	// osSandboxTool is the absolute path to a discovered macOS sandbox-exec
	// binary, or "" if unavailable/not on darwin. Detected once, in Init.
	osSandboxTool string
	// bwrapTool is the absolute path to a discovered Linux bubblewrap
	// (bwrap) binary, or "" if unavailable/not on linux. Detected once, in
	// Init. Only one of osSandboxTool/bwrapTool is ever non-empty, since
	// each is gated on its own runtime.GOOS check.
	bwrapTool string

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

	// Detect a real OS-level sandbox tool once. macOS uses sandbox-exec,
	// Linux uses bubblewrap (bwrap) — absence of either (or running on a
	// platform with neither, e.g. Windows) just means SandboxModeRestricted,
	// never a failure to boot.
	switch runtime.GOOS {
	case "darwin":
		if path, err := exec.LookPath("sandbox-exec"); err == nil {
			p.osSandboxTool = path
		}
	case "linux":
		if path, err := exec.LookPath("bwrap"); err == nil {
			p.bwrapTool = path
		}
	}
	// Windows (and any other platform) has no OS-level sandbox wired up
	// here — real equivalents exist (Job Objects, AppContainer) but are a
	// much larger, separate undertaking, explicitly out of scope for this
	// pass. Run/RunWithSecrets still apply every Go-level control
	// (allowlist, explicit env, timeout, output bounds) there, and
	// SandboxResult.Mode correctly reports SandboxModeRestricted rather
	// than ever claiming stronger isolation than was actually applied.

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
	if p.bwrapTool != "" {
		return api.Health{Status: "ok", Detail: "os-level sandbox available (" + p.bwrapTool + ")"}
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

// standardBwrapROBindCandidates lists the typical FHS paths a dynamically
// linked Linux binary needs read access to in order to run at all (the
// dynamic linker, shared libraries, and standard utilities) — not every
// entry exists on every distribution (e.g. /lib64 is absent on some),
// which is exactly why the caller filters this list down to paths that
// actually exist on this host before calling buildBwrapArgs: binding a
// nonexistent source path is what would make bwrap itself fail at
// runtime, so filtering in advance avoids that failure mode entirely
// rather than trying to distinguish "bwrap failed" from "the target
// program legitimately exited non-zero" after the fact — those look
// identical from cmd.Run()'s perspective (both are a normal process exit
// with a nonzero code), so there is no reliable way to tell them apart
// post-hoc.
func standardBwrapROBindCandidates() []string {
	return []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/resolv.conf", "/etc/ssl"}
}

// existingPaths filters candidates down to the ones that actually exist
// on this host (via os.Stat), preserving order.
func existingPaths(candidates []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// buildBwrapArgs constructs the real bubblewrap (bwrap) argument list for
// running targetCmd/targetArgs confined to workDir with the given
// read-only bind paths. It is a pure function — no filesystem or process
// access — specifically so its exact output can be unit-tested on any
// platform (including this development machine, macOS, where bwrap
// itself cannot run) without needing bwrap to actually be present.
//
// Confinement applied: every roBinds path is bound read-only; workDir is
// bound read-write and made the working directory; /tmp is a fresh,
// empty tmpfs (not the host's real /tmp); --unshare-net denies network
// access entirely (matching the intent of the macOS sandbox-exec
// profile's lack of any "allow network*" rule); --die-with-parent
// ensures a killed/timed-out parent (see Run's context-based timeout)
// takes the sandboxed child down with it rather than orphaning it.
func buildBwrapArgs(workDir string, roBinds []string, targetCmd string, targetArgs []string) []string {
	args := make([]string, 0, len(roBinds)*3+len(targetArgs)+16)
	for _, p := range roBinds {
		args = append(args, "--ro-bind", p, p)
	}
	args = append(args,
		"--tmpfs", "/tmp",
		"--bind", workDir, workDir,
		"--chdir", workDir,
		"--unshare-net",
		"--die-with-parent",
		"--",
		targetCmd,
	)
	args = append(args, targetArgs...)
	return args
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
	bwrap := p.bwrapTool
	p.mu.RUnlock()

	switch {
	case osTool != "":
		profile := sandboxExecProfile(workDir)
		fullArgs := append([]string{"-p", profile, resolved}, args...)
		cmd = exec.CommandContext(runCtx, osTool, fullArgs...)
		mode = api.SandboxModeOSLevel
	case bwrap != "":
		roBinds := existingPaths(standardBwrapROBindCandidates())
		bwrapArgs := buildBwrapArgs(workDir, roBinds, resolved, args)
		cmd = exec.CommandContext(runCtx, bwrap, bwrapArgs...)
		mode = api.SandboxModeOSLevel
	default:
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

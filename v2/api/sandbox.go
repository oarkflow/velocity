package api

import (
	"context"
	"time"
)

// SandboxMode reports which level of isolation a SandboxService actually
// applied to a given Run call — callers making a security decision must
// be able to tell the difference, not assume the strongest mode was used.
type SandboxMode string

const (
	// SandboxModeOSLevel means a real OS-provided sandboxing mechanism
	// wrapped the process (e.g. macOS sandbox-exec, Linux bubblewrap),
	// found and used automatically because it was available on this host.
	SandboxModeOSLevel SandboxMode = "os-level"
	// SandboxModeRestricted means no OS sandbox tool was found/usable, so
	// only the Go-level controls applied: command allowlist, explicit
	// (not inherited) environment, timeout, and output-size limits. This
	// is real protection, but weaker than OS-level isolation — no
	// filesystem/network confinement.
	SandboxModeRestricted SandboxMode = "restricted-env-only"
)

// SandboxOptions configures one Run call.
type SandboxOptions struct {
	// Env is the COMPLETE environment the subprocess receives — the
	// subprocess does NOT inherit this process's environment (which may
	// contain the host application's own secrets/config) unless an entry
	// is explicitly included here.
	Env map[string]string
	// WorkDir is the subprocess's working directory. Empty means a fresh
	// temp directory created for this Run and removed afterward — never
	// the caller's own cwd by default, to avoid accidental access to
	// unrelated files.
	WorkDir string
	// Timeout bounds the subprocess's total runtime; exceeding it kills
	// the process. Zero means a sane default (implementation-defined,
	// documented by the concrete plugin) is applied — Run never blocks
	// forever.
	Timeout time.Duration
	// MaxOutputBytes bounds how much combined stdout+stderr is captured;
	// output beyond this is truncated (the subprocess itself is not
	// killed for exceeding it, only the captured buffer is capped),
	// so a runaway process can't exhaust memory. Zero means a sane
	// implementation-defined default.
	MaxOutputBytes int
}

// SandboxResult is what Run returns.
type SandboxResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	// Mode reports which isolation level actually applied — see
	// SandboxMode's doc comments. Never assume SandboxModeOSLevel without
	// checking this field.
	Mode SandboxMode
	// Truncated is true if Stdout/Stderr were cut short by MaxOutputBytes.
	Truncated bool
}

// SandboxService runs an external command with explicit, minimal
// privilege: no shell interpretation (arguments are never passed through
// /bin/sh -c, so shell metacharacters in an argument are inert data, not
// commands), an enforced command allowlist, an explicit (never inherited)
// environment, a timeout, and bounded output capture. It automatically
// upgrades to a real OS-level sandbox (SandboxModeOSLevel) when one is
// available on the host, and is honest in SandboxResult.Mode about when
// it could not.
//
// This is the mechanism a caller uses to run a command with secrets
// injected as environment variables without ever writing them to disk or
// letting them leak into the host process's own environment or logs —
// see RunWithSecrets.
//
// Service name: "sandbox".
type SandboxService interface {
	// Run executes name with args under the given options. name must be
	// on the plugin's configured command allowlist (see the concrete
	// plugin's "allowed_commands" config) or Run returns an error without
	// executing anything.
	Run(ctx context.Context, name string, args []string, opts SandboxOptions) (SandboxResult, error)

	// RunWithSecrets looks up each name in secretNames via the given
	// SecretService, injects it into the subprocess's environment under
	// the same name (uppercased, matching standard env-var convention),
	// merges in any additional opts.Env entries, and Runs. Secrets are
	// never written to disk, logged, or included in SandboxResult — only
	// exposed to the subprocess's own environment for its lifetime.
	RunWithSecrets(ctx context.Context, secrets SecretService, secretNames []string, name string, args []string, opts SandboxOptions) (SandboxResult, error)
}

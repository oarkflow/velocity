//go:build !linux && !windows
// +build !linux,!windows

package exec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

// ErrNamespaceNotSupported is returned when namespace sandboxing is attempted on non-Linux systems
var ErrNamespaceNotSupported = errors.New("namespace sandboxing is only supported on Linux")

// NamespaceSandbox implements execution in Linux namespaces
// On non-Linux systems, this falls back to host execution with a warning
type NamespaceSandbox struct {
	// Options to enable specific namespaces (only effective on Linux)
	EnablePID   bool
	EnableNet   bool
	EnableIPC   bool
	EnableUTS   bool
	EnableMount bool
}

func NewNamespaceSandbox() *NamespaceSandbox {
	return &NamespaceSandbox{
		EnablePID:   true,
		EnableIPC:   true,
		EnableUTS:   true,
		EnableMount: true,
	}
}

// Run executes the command. On non-Linux systems, this falls back to host execution or a platform-specific sandbox.
func (s *NamespaceSandbox) Run(ctx context.Context, opts SandboxOptions) (*ExecutionResult, error) {
	command := opts.Command
	args := opts.Args

	// On macOS, try to use sandbox-exec for basic isolation
	if runtime.GOOS == "darwin" {
		// Simple profile: allow everything except what we might want to restrict
		// For now, just a placeholder profile that allow all but shows we can use it
		sandboxArgs := []string{
			"-p", "(version 1)(allow default)",
			command,
		}
		command = "sandbox-exec"
		args = append(sandboxArgs, args...)
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	res, err := runCommand(cmd)
	if err != nil {
		if opts.AllowFallback && runtime.GOOS == "darwin" && command == "sandbox-exec" {
			host := &HostSandbox{}
			return host.Run(ctx, opts)
		}
		return nil, err
	}
	if opts.Strict && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("%w: strict mode requested on %s", ErrNamespaceNotSupported, runtime.GOOS)
	}
	return res, nil
}

//go:build windows
// +build windows

package exec

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// WindowsSandbox provides best-effort process isolation on Windows.
// It isolates process groups and avoids shell execution.
type WindowsSandbox struct{}

func (s *WindowsSandbox) Run(ctx context.Context, opts SandboxOptions) (*ExecutionResult, error) {
	if opts.Strict && opts.SeccompProfile != "" {
		return nil, fmt.Errorf("seccomp is not supported on windows")
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}

	return runCommand(cmd)
}

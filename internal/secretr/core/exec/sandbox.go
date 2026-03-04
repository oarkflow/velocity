package exec

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// SandboxProvider defines the interface for sandboxed execution
type SandboxProvider interface {
	Run(ctx context.Context, opts SandboxOptions) (*ExecutionResult, error)
}

// SandboxOptions holds options for sandboxed execution
type SandboxOptions struct {
	Command        string
	Args           []string
	Env            []string
	Dir            string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	Limits         *ResourceLimits
	SeccompProfile string
	Strict         bool
	AllowFallback  bool
}

// ResourceLimits defines resource limits for execution
type ResourceLimits struct {
	CPUMax    string // e.g. "100000 100000"
	MemoryMax int64  // bytes
}

// HostSandbox implements direct host execution (no isolation)
type HostSandbox struct{}

func (s *HostSandbox) Run(ctx context.Context, opts SandboxOptions) (*ExecutionResult, error) {
	if opts.Strict && (opts.Limits != nil || opts.SeccompProfile != "") {
		return nil, fmt.Errorf("strict sandbox requested but host sandbox cannot enforce limits/seccomp")
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	return runCommand(cmd)
}

// runCommand handles the common command execution logic (Start + Wait)
func runCommand(cmd *exec.Cmd) (*ExecutionResult, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return waitCommand(cmd)
}

// waitCommand waits for a started command to finish and returns the result
func waitCommand(cmd *exec.Cmd) (*ExecutionResult, error) {
	var exitCode int
	var errStr string
	success := true

	err := cmd.Wait()
	if err != nil {
		success = false
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
		errStr = err.Error()
	}

	return &ExecutionResult{
		ExitCode: exitCode,
		Success:  success,
		Error:    errStr,
	}, nil
}

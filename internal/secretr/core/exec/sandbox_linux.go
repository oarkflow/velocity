//go:build linux
// +build linux

package exec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// NamespaceSandbox implements execution in Linux namespaces
type NamespaceSandbox struct {
	// Options to enable specific namespaces
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
		EnableMount: true, // Requires simple filesystem isolation setup
		// Net is usually too restrictive without proper veth setup, enabled only if requested specifically
	}
}

func (s *NamespaceSandbox) Run(ctx context.Context, opts SandboxOptions) (*ExecutionResult, error) {
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	// Set syscall attributes for namespacing
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: 0,

	}

	if s.EnablePID {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWPID
	}
	if s.EnableIPC {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWIPC
	}
	if s.EnableUTS {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUTS
	}
	if s.EnableNet {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	}
	if s.EnableMount {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS
	}

	// Cgroups Setup
	var cg *CgroupManager
	if opts.Limits != nil {
		cg = NewCgroupManager("sandbox-" + strconv.Itoa(os.Getpid()))
		if err := cg.Setup(*opts.Limits); err != nil {
			if opts.Strict {
				return nil, err
			}
			cg = nil
		}
	}
	if cg != nil {
		defer func() {
			_ = cg.Cleanup()
		}()
	}

	if err := cmd.Start(); err != nil {
		if opts.AllowFallback && shouldFallbackToHost(err) {
			host := &HostSandbox{}
			return host.Run(ctx, opts)
		}
		return nil, err
	}

	// Add process to cgroup
	if cg != nil {
		_ = cg.AddProcess(cmd.Process.Pid)
	}

	// Seccomp policy handling:
	// Direct per-process seccomp installation is not yet supported in this code path.
	// In strict mode, fail closed if seccomp is requested.
	if opts.SeccompProfile != "" && opts.Strict {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("seccomp profile requested in strict mode but runtime seccomp attach is not available")
	}

	// Wait for completion
	return waitCommand(cmd)
}

func shouldFallbackToHost(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)
}

// Placeholder for io import usage
var _ io.Reader

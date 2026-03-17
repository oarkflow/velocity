package exec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestHostSandbox(t *testing.T) {
	sandbox := &HostSandbox{}
	ctx := context.Background()

	// Test case 1: Simple echo
	var stdout, stderr bytes.Buffer
	opts := SandboxOptions{
		Command: "echo",
		Args:    []string{"hello", "world"},
		Stdout:  &stdout,
		Stderr:  &stderr,
	}

	res, err := sandbox.Run(ctx, opts)
	if err != nil {
		t.Fatalf("HostSandbox.Run failed: %v", err)
	}

	if !res.Success {
		t.Errorf("Expected success, got failure. Error: %s", res.Error)
	}
	if strings.TrimSpace(stdout.String()) != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", stdout.String())
	}
}

func TestNamespaceSandbox(t *testing.T) {
	// Check if we can use namespaces (simplified check, real check is trying it)
	// Usually requires root or user namespaces enabled
	if os.Getuid() != 0 {
		// Attempt to check if user namespaces are enabled
		// This is a rough check, we'll try running a dummy command first
		cmd := exec.Command("unshare", "--user", "--pid", "echo", "check")
		if err := cmd.Run(); err != nil {
			t.Skip("Skipping NamespaceSandbox test: requires root or user namespaces support")
		}
	}

	sandbox := NewNamespaceSandbox()
	// Disable mount for test simplicity if strict isolation isn't guaranteed
	// But let's keep defaults and see.
	// For testing as non-root, we might need CLONE_NEWUSER if available, but the current implementation doesn't strictly add it.
	// Let's modify NewNamespaceSandbox defaults in the test or keep as is.
	// NOTE: standard CLONE_NEWPID etc usually require CAP_SYS_ADMIN unless CLONE_NEWUSER is also used.
	// The current implementation in sandbox.go only adds PID, IPC, UTS, Net, Mount which implies high privileges.

	ctx := context.Background()

	var stdout, stderr bytes.Buffer
	opts := SandboxOptions{
		Command: "echo",
		Args:    []string{"sandboxed"},
		Stdout:  &stdout,
		Stderr:  &stderr,
	}

	// This might fail if not root, so we check error
	res, err := sandbox.Run(ctx, opts)
	if err != nil {
		// If permission denied, checking it is expected behavior for non-root
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("Namespace creation not permitted (run as root to verify)")
		}
		t.Fatalf("NamespaceSandbox.Run failed: %v", err)
	}

	if !res.Success {
		// It might fail inside Run if syscall fails
		if strings.Contains(res.Error, "operation not permitted") {
			t.Skip("Namespace creation not permitted (run as root to verify)")
		}
		t.Errorf("Expected success, got failure. Error: %s", res.Error)
	} else {
		if strings.TrimSpace(stdout.String()) != "sandboxed" {
			t.Errorf("Expected 'sandboxed', got '%s'", stdout.String())
		}
	}
}

func TestExecutorWithSandbox(t *testing.T) {
	// Test the high level Executor integration
	cfg := ExecutorConfig{
		Isolation: IsolationHost,
	}

	executor := NewExecutor(cfg)
	ctx := context.Background()

	res, err := executor.Execute(ctx, ExecuteOptions{
		Command: "echo",
		Args:    []string{"integration"},
	})
	if err != nil {
		t.Fatalf("Executor.Execute failed: %v", err)
	}

	if !res.Success {
		t.Errorf("Expected success")
	}
	if strings.TrimSpace(res.Stdout) != "integration" {
		t.Errorf("Expected 'integration', got '%s'", res.Stdout)
	}
}

func TestHostSandboxStrictMode(t *testing.T) {
	sandbox := &HostSandbox{}
	ctx := context.Background()

	var stdout, stderr bytes.Buffer
	opts := SandboxOptions{
		Command: "echo",
		Args:    []string{"strict"},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Strict:  true,
		Limits:  &ResourceLimits{MemoryMax: 1024},
	}

	if _, err := sandbox.Run(ctx, opts); err == nil {
		t.Fatalf("expected strict host sandbox to fail when limits are requested")
	}
}

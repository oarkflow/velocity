// Package exec provides secure command execution with secret injection.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrCommandFailed  = errors.New("exec: command execution failed")
	ErrTimeout        = errors.New("exec: command timed out")
	ErrSecretNotFound = errors.New("exec: secret not found")
)

// SecretBinding maps a secret to an environment variable or file
type SecretBinding struct {
	SecretID   types.ID `json:"secret_id"`
	TargetType string   `json:"target_type"` // "env", "file"
	TargetName string   `json:"target_name"` // env var name or file path
}

// ExecutionResult represents the result of command execution
type ExecutionResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration_ns"`
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
}

// SecretRetriever is a callback to retrieve secret values
type SecretRetriever func(ctx context.Context, secretID types.ID) (string, error)

// Executor handles secure command execution with secrets
type Executor struct {
	crypto          *crypto.Engine
	auditEngine     *audit.Engine
	secretRetriever SecretRetriever
	defaultTimeout  time.Duration
	sandbox         SandboxProvider
	resourceLimits  *ResourceLimits
	seccompProfile  string
	strictSandbox   bool
}

// IsolationLevel defines the level of isolation for execution
type IsolationLevel string

const (
	IsolationAuto      IsolationLevel = "auto"
	IsolationHost      IsolationLevel = "host"
	IsolationNamespace IsolationLevel = "ns"
)

// ExecutorConfig configures the executor
type ExecutorConfig struct {
	AuditEngine     *audit.Engine
	SecretRetriever SecretRetriever
	DefaultTimeout  time.Duration
	Isolation       IsolationLevel
	ResourceLimits  *ResourceLimits
	SeccompProfile  string
	StrictSandbox   bool
}

// NewExecutor creates a new secure executor
func NewExecutor(cfg ExecutorConfig) *Executor {
	timeout := cfg.DefaultTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	var sandbox SandboxProvider
	switch cfg.Isolation {
	case IsolationNamespace:
		sandbox = NewNamespaceSandbox()
	case IsolationAuto:
		if runtime.GOOS == "linux" {
			sandbox = NewNamespaceSandbox()
		} else {
			sandbox = NewPlatformSandbox()
		}
	default:
		sandbox = NewPlatformSandbox()
	}

	return &Executor{
		crypto:          crypto.NewEngine(""),
		auditEngine:     cfg.AuditEngine,
		secretRetriever: cfg.SecretRetriever,
		defaultTimeout:  timeout,
		sandbox:         sandbox,
		resourceLimits:  cfg.ResourceLimits,
		seccompProfile:  cfg.SeccompProfile,
		strictSandbox:   cfg.StrictSandbox,
	}
}

// ExecuteOptions holds execution options
type ExecuteOptions struct {
	Command    string
	Args       []string
	WorkingDir string
	Timeout    time.Duration
	Bindings   []SecretBinding
	ActorID    types.ID
	Env        map[string]string
}

// Execute executes a command with secret bindings
func (e *Executor) Execute(ctx context.Context, opts ExecuteOptions) (*ExecutionResult, error) {
	start := time.Now()

	// Set timeout
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = e.defaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build environment with secrets
	env := os.Environ()
	tempFiles := []string{}
	defer func() {
		// Clean up temp files
		for _, f := range tempFiles {
			os.Remove(f)
		}
	}()

	// Add custom env vars
	for k, v := range opts.Env {
		env = append(env, k+"="+v)
	}

	// Process secret bindings
	for _, binding := range opts.Bindings {
		if e.secretRetriever == nil {
			continue
		}

		value, err := e.secretRetriever(ctx, binding.SecretID)
		if err != nil {
			return &ExecutionResult{
				ExitCode: -1,
				Error:    ErrSecretNotFound.Error() + ": " + string(binding.SecretID),
				Success:  false,
				Duration: time.Since(start),
			}, nil
		}

		switch binding.TargetType {
		case "env":
			// Add to environment
			env = append(env, binding.TargetName+"="+value)
		case "file":
			// Write to temporary file
			tempFile, err := e.writeSecretFile(binding.TargetName, value)
			if err != nil {
				return &ExecutionResult{
					ExitCode: -1,
					Error:    "failed to write secret file: " + err.Error(),
					Success:  false,
					Duration: time.Since(start),
				}, nil
			}
			tempFiles = append(tempFiles, tempFile)
			// Add file path to environment
			env = append(env, binding.TargetName+"_FILE="+tempFile)
		}

		// Zero the secret value from memory
		security.ZeroizeString(&value)
	}

	var stdout, stderr bytes.Buffer

	// Prepare Sandbox Options
	sbOpts := SandboxOptions{
		Command:        opts.Command,
		Args:           opts.Args,
		Env:            env,
		Dir:            opts.WorkingDir,
		Stdout:         &stdout,
		Stderr:         &stderr,
		Limits:         e.resourceLimits,
		SeccompProfile: e.seccompProfile,
		Strict:         e.strictSandbox,
		AllowFallback:  !e.strictSandbox,
	}

	// Execute via Sandbox
	res, err := e.sandbox.Run(ctx, sbOpts)

	duration := time.Since(start)

	result := &ExecutionResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.ExitCode = -1
		result.Error = ErrTimeout.Error()
		result.Success = false
	} else if err != nil {
		// e.sandbox.Run returns *ExecutionResult for exit code info if available
		if res != nil {
			result.ExitCode = res.ExitCode
			result.Error = res.Error
			result.Success = res.Success
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
			result.Success = false
		}
	} else {
		result.ExitCode = res.ExitCode
		result.Success = res.Success
		result.Error = res.Error
	}

	// Audit log
	if e.auditEngine != nil {
		sandboxType := fmt.Sprintf("%T", e.sandbox)
		e.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "exec",
			Action:       "command_execute",
			ActorID:      opts.ActorID,
			ActorType:    "identity",
			ResourceType: "command",
			Success:      result.Success,
			Details: types.Metadata{
				"command":      opts.Command,
				"exit_code":    result.ExitCode,
				"duration_ms":  duration.Milliseconds(),
				"secret_count": len(opts.Bindings),
				"sandbox_type": sandboxType,
			},
		})
	}

	return result, nil
}

// writeSecretFile writes a secret to a temporary file with secure permissions
func (e *Executor) writeSecretFile(name, value string) (string, error) {
	// Create temp file with secure permissions
	f, err := os.CreateTemp("", "secretr-*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Set restrictive permissions
	if err := f.Chmod(0600); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	// Write secret
	if _, err := f.WriteString(value); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	return f.Name(), nil
}

// ExecuteWithEnv executes a simple command with environment variables
func (e *Executor) ExecuteWithEnv(ctx context.Context, command string, args []string, env map[string]string, actorID types.ID) (*ExecutionResult, error) {
	return e.Execute(ctx, ExecuteOptions{
		Command: command,
		Args:    args,
		Env:     env,
		ActorID: actorID,
	})
}

// ExecuteWithSecrets executes a command with secret bindings
func (e *Executor) ExecuteWithSecrets(ctx context.Context, command string, args []string, bindings []SecretBinding, actorID types.ID) (*ExecutionResult, error) {
	return e.Execute(ctx, ExecuteOptions{
		Command:  command,
		Args:     args,
		Bindings: bindings,
		ActorID:  actorID,
	})
}

// Close cleans up resources
func (e *Executor) Close() error {
	return e.crypto.Close()
}

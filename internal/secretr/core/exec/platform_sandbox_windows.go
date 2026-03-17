//go:build windows
// +build windows

package exec

// NewPlatformSandbox returns the default sandbox for Windows.
func NewPlatformSandbox() SandboxProvider {
	return &WindowsSandbox{}
}

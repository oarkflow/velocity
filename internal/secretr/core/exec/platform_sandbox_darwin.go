//go:build darwin
// +build darwin

package exec

// NewPlatformSandbox returns the default sandbox for macOS.
func NewPlatformSandbox() SandboxProvider {
	return NewNamespaceSandbox()
}

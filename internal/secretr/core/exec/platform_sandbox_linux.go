//go:build linux
// +build linux

package exec

// NewPlatformSandbox returns the default sandbox for Linux.
func NewPlatformSandbox() SandboxProvider {
	return NewNamespaceSandbox()
}

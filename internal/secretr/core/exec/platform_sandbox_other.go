//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package exec

// NewPlatformSandbox returns the default sandbox for unsupported platforms.
func NewPlatformSandbox() SandboxProvider {
	return &HostSandbox{}
}

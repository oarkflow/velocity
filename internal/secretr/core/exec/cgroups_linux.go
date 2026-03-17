//go:build linux
// +build linux

package exec

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// CgroupManager manages cgroups v2
type CgroupManager struct {
	CgroupRoot string
	Name       string
}

// NewCgroupManager creates a new cgroup manager
func NewCgroupManager(name string) *CgroupManager {
	return &CgroupManager{
		CgroupRoot: "/sys/fs/cgroup",
		Name:       name,
	}
}

// Setup creates the cgroup and sets limits
func (c *CgroupManager) Setup(limits ResourceLimits) error {
	path := filepath.Join(c.CgroupRoot, "secretr", c.Name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("cgroup create failed: %w", err)
	}

	// Set CPU max (quota period)
	if limits.CPUMax != "" {
		if err := c.write(path, "cpu.max", limits.CPUMax); err != nil {
			return err
		}
	}

	// Set Memory max
	if limits.MemoryMax > 0 {
		if err := c.write(path, "memory.max", strconv.FormatInt(limits.MemoryMax, 10)); err != nil {
			return err
		}
	}

	return nil
}

// AddProcess adds a process to the cgroup
func (c *CgroupManager) AddProcess(pid int) error {
	path := filepath.Join(c.CgroupRoot, "secretr", c.Name)
	return c.write(path, "cgroup.procs", strconv.Itoa(pid))
}

// Cleanup removes the cgroup
func (c *CgroupManager) Cleanup() error {
	path := filepath.Join(c.CgroupRoot, "secretr", c.Name)
	return os.Remove(path)
}

func (c *CgroupManager) write(path, file, data string) error {
	return os.WriteFile(filepath.Join(path, file), []byte(data), 0644)
}

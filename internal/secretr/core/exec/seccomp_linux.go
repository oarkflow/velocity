//go:build linux
// +build linux

package exec

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// LoadSeccompProfile loads a seccomp profile
func LoadSeccompProfile(profile string) (*libseccomp.ScmpFilter, error) {
	// Start with default action based on profile
	var defaultAction libseccomp.ScmpAction
	if profile == "strict" {
		defaultAction = libseccomp.ActErrno
	} else {
		defaultAction = libseccomp.ActAllow
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, err
	}

	// For "strict" profile, whitelist basic syscalls
	if profile == "strict" {
		syscalls := []string{
			"read", "write", "exit", "exit_group", "sigreturn",
			"brk", "mmap", "munmap", "fstat", "lseek",
			"rt_sigaction", "rt_sigprocmask", "futex",
			"gettid", "getpid", "tgkill",
		}

		for _, name := range syscalls {
			id, err := libseccomp.GetSyscallFromName(name)
			if err != nil {
				continue
			}
			if err := filter.AddRule(id, libseccomp.ActAllow); err != nil {
				return nil, err
			}
		}
	}

	return filter, nil
}

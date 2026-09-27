//go:build !windows

package lsm

import (
	"os"

	"golang.org/x/sys/unix"
)

// platformPosixFsync issues the plain POSIX fsync(2) syscall directly,
// bypassing Darwin's stronger (and slower) F_FULLFSYNC that os.File.Sync()
// uses there — see FsyncMode's doc comment in wal.go for the full
// rationale. On Linux this is identical to os.File.Sync() (Linux's
// os.File.Sync() already calls plain fsync(2)).
func platformPosixFsync(f *os.File) error {
	return unix.Fsync(int(f.Fd()))
}

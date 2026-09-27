//go:build windows

package lsm

import "os"

// platformPosixFsync on Windows falls back to the exact same call
// FsyncFull uses (os.File.Sync(), i.e. FlushFileBuffers). Researched
// rather than assumed: unlike Darwin (plain fsync(2) vs fcntl(F_FULLFSYNC))
// or Linux (fsync(2) is the only mechanism at this level either way),
// Windows exposes no weaker/faster alternative to FlushFileBuffers through
// the Win32 API that Go's standard library (or golang.org/x/sys/windows)
// surfaces at this level — FlushFileBuffers is already the strong,
// physical-media flush. So on Windows, FsyncMode's "posix" and "full"
// options are the same operation: there is no meaningful weaker mode to
// offer here, and pretending otherwise would misrepresent the guarantee.
// This is a documented behavioral difference from Unix, not a bug: on
// Windows, fsync_mode: "posix" buys no additional speed over the default.
func platformPosixFsync(f *os.File) error {
	return f.Sync()
}

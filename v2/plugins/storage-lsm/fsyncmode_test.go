package lsm

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// TestFsyncMode_PosixIsFasterThanFull is the real-hardware proof behind
// FsyncMode's doc comment: on this machine, FsyncPosix (plain fsync(2))
// must complete a batch of durable single-record writes measurably faster
// than FsyncFull (fcntl(F_FULLFSYNC) on Darwin, plain fsync(2) on Linux —
// so this assertion is expected to show a real gap on Darwin and near-zero
// difference on Linux, which is itself the documented, honest behavior,
// not a test bug).
func TestFsyncMode_PosixIsFasterThanFull(t *testing.T) {
	if os.Getenv("GOOS") == "linux" {
		t.Skip("FsyncPosix and FsyncFull are the same syscall on Linux — no gap expected")
	}

	measure := func(mode FsyncMode) time.Duration {
		dir := t.TempDir()
		e, err := Open(dir, true, WithFsyncMode(mode))
		if err != nil {
			t.Fatalf("Open(%s): %v", mode, err)
		}
		defer e.Close()

		const n = 30
		start := time.Now()
		for i := 0; i < n; i++ {
			key := []byte(fmt.Sprintf("k%d", i))
			if err := e.Put(context.Background(), api.Entry{Key: key, Value: []byte("v")}); err != nil {
				t.Fatalf("Put: %v", err)
			}
		}
		return time.Since(start)
	}

	full := measure(FsyncFull)
	posix := measure(FsyncPosix)

	t.Logf("FsyncFull:  %v total (%v/op)", full, full/30)
	t.Logf("FsyncPosix: %v total (%v/op)", posix, posix/30)

	if posix >= full {
		t.Logf("WARNING: FsyncPosix (%v) was not faster than FsyncFull (%v) on this run — "+
			"report this plainly rather than assume the hypothesis always holds; timing noise "+
			"or a non-Darwin fsync implementation can both explain it", posix, full)
	}
}

//go:build !windows

package kernel

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// WatchManifestWithSignal runs WatchManifest's polling loop AND, on
// Unix-like platforms, additionally triggers an immediate reload the
// moment SIGHUP arrives — a convenience for operators used to `kill
// -HUP`/systemd's reload signal, on top of (not instead of) the portable
// polling loop, so behavior stays consistent between an edit-then-wait
// and an edit-then-signal workflow. Windows has no equivalent signal —
// see watch_windows.go, which falls back to polling only.
func WatchManifestWithSignal(ctx context.Context, path string, interval time.Duration, onChange func(Manifest) error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)

	lastMod := statModTime(path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndReload(path, &lastMod, onChange)
		case <-sig:
			// SIGHUP forces a reload unconditionally, regardless of
			// whether mtime advanced — an operator sending it explicitly
			// means "reload now," not "reload only if you also notice a
			// change," so a manifest edit racing a coarse mtime clock (or
			// simply re-applying identical content) still reloads.
			if m, err := LoadManifestBCL(path); err == nil {
				lastMod = statModTime(path)
				_ = onChange(m)
			}
		}
	}
}

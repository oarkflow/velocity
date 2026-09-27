package kernel

import (
	"context"
	"os"
	"time"
)

// WatchManifest polls path's mtime every interval and calls onChange with
// the freshly parsed Manifest whenever the file's modification time
// advances. It is the cross-platform (Linux/Windows/macOS) reload
// trigger: polling rather than a filesystem-event API (e.g. fsnotify) is
// a deliberate choice — it needs no new dependency and behaves
// identically on every platform, at the cost of up to one `interval` of
// detection latency, an acceptable trade for a manifest reload (not a
// latency-sensitive hot path). Runs until ctx is cancelled.
//
// A changed file that fails to parse (bad JSON) is skipped silently by
// this function — callers that want to log the failure should do so
// inside onChange by calling kernel.LoadManifestBCL themselves if they
// need the parse error; WatchManifest only invokes onChange when parsing
// already succeeded, since Kernel.Reload's own contract is "operate on a
// valid Manifest," matching Boot. Either way, a bad edit never stops the
// watch loop or crashes the process — it just waits for the next change.
//
// On non-Windows platforms, see WatchManifestWithSignal for an
// additional SIGHUP-triggered immediate reload alongside polling — plain
// WatchManifest alone is already fully cross-platform including Windows,
// which has no SIGHUP.
func WatchManifest(ctx context.Context, path string, interval time.Duration, onChange func(Manifest) error) {
	lastMod := statModTime(path)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndReload(path, &lastMod, onChange)
		}
	}
}

func statModTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func checkAndReload(path string, lastMod *time.Time, onChange func(Manifest) error) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if !fi.ModTime().After(*lastMod) {
		return
	}
	*lastMod = fi.ModTime()
	m, err := LoadManifestBCL(path)
	if err != nil {
		return // malformed edit — skip, keep watching for the next one
	}
	_ = onChange(m)
}

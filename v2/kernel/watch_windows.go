//go:build windows

package kernel

import (
	"context"
	"time"
)

// WatchManifestWithSignal on Windows is identical to plain WatchManifest
// — Windows has no SIGHUP equivalent that would be worth emulating here
// (Windows services have their own separate control-signal mechanism,
// out of scope for this cross-platform manifest-reload feature). Windows
// operators get file-watching (polling) only; this is an intentional,
// documented platform difference, not an oversight.
func WatchManifestWithSignal(ctx context.Context, path string, interval time.Duration, onChange func(Manifest) error) {
	WatchManifest(ctx, path, interval, onChange)
}

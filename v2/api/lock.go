package api

import (
	"context"
	"time"
)

// LockHandle is returned by LockService.Acquire and lets the holder
// release or extend the lock it was granted.
type LockHandle interface {
	Release(ctx context.Context) error
	Renew(ctx context.Context, ttl time.Duration) error
}

// LockService is a TTL-based lock, ported from v1's pkg/lock
// (VelocityLocker). Acquire does not block or retry: a key already held
// returns an error immediately, mirroring v1's behavior — callers wanting
// blocking-with-retry semantics implement that themselves on top of this.
//
// Ported implementations (see plugins/lock) are, like v1's own
// VelocityLocker, NOT a true distributed compare-and-swap primitive; see
// that package's doc comment for the exact guarantee it does provide.
type LockService interface {
	Acquire(ctx context.Context, key string, ttl time.Duration) (LockHandle, error)
	IsLocked(ctx context.Context, key string) (bool, error)
}

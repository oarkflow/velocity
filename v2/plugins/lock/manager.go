package lock

import (
	"context"
	"fmt"
	"time"
)

// Entity/stage lock helpers, ported from v1's pkg/lock.LockManager. These
// are convenience wrappers over Acquire/IsLocked with a fixed key scheme
// ("entry:<id>:user:<user>" / "stage:<id>:user:<user>") — not part of
// api.LockService, since they're a naming convention on top of the
// generic service, not a distinct capability.

func (p *Plugin) AcquireEntryLock(ctx context.Context, entryID, userID string, ttl time.Duration) (release func(context.Context) error, err error) {
	h, err := p.Acquire(ctx, fmt.Sprintf("entry:%s:user:%s", entryID, userID), ttl)
	if err != nil {
		return nil, err
	}
	return h.Release, nil
}

func (p *Plugin) IsEntryLocked(ctx context.Context, entryID string) (bool, error) {
	return p.IsLocked(ctx, fmt.Sprintf("entry:%s", entryID))
}

func (p *Plugin) AcquireStageLock(ctx context.Context, stageID, userID string, ttl time.Duration) (release func(context.Context) error, err error) {
	h, err := p.Acquire(ctx, fmt.Sprintf("stage:%s:user:%s", stageID, userID), ttl)
	if err != nil {
		return nil, err
	}
	return h.Release, nil
}

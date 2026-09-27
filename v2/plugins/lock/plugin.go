// Package lock implements Velocity v2's "lock" plugin: a TTL-based lock
// service, ported from v1's pkg/lock (VelocityLocker/LockManager).
//
// Correctness note (read before relying on this for cross-process
// mutual exclusion): v1's VelocityLocker itself was not a true atomic
// compare-and-swap primitive either — it did a Get, checked the parsed
// expiry, and then a separate Put, with a race window between the two
// visible to any other caller doing the same sequence concurrently. This
// plugin makes the SAME lock correct WITHIN one process by guarding the
// Get-check-Put sequence with an in-memory per-key mutex (via a single
// package-level striped lock map), which v1 did not have at all. Across
// multiple processes/nodes sharing the same underlying storage, the same
// race v1 had still exists here, because api.KVService has no atomic
// "put if absent" primitive to build a real distributed CAS on — closing
// that gap needs a StorageBackend-level compare-and-swap operation, which
// is out of scope for this pass and noted as a follow-up.
package lock

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

var (
	ErrLockAlreadyAcquired = errors.New("lock: already acquired by another holder")
	ErrLockNotHeld         = errors.New("lock: not held")
	ErrLockExpired         = errors.New("lock: expired")
)

const keyPrefix = "lock:"

// Plugin implements api.Plugin + api.LockService atop a looked-up
// api.KVService.
type Plugin struct {
	kvDep string
	kv    api.KVService

	// mu guards the whole Acquire/Release/Renew/IsLocked critical section
	// per-process (see package doc). A single mutex, not a per-key striped
	// map, is used deliberately for simplicity — lock operations are
	// expected to be infrequent and short, so one mutex is not a
	// meaningful bottleneck; a striped map would be a natural follow-up if
	// profiling ever shows otherwise.
	mu sync.Mutex
}

// NewPlugin constructs the lock plugin. kvDep selects which plugin's
// Dependencies() ordering this waits on for boot purposes (default "kv");
// the service is always looked up under the fixed name "kv".
func NewPlugin(kvDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	return &Plugin{kvDep: kvDep}
}

func (p *Plugin) Name() string           { return "lock" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.kvDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	svc, ok := k.Registry().Lookup("kv")
	if !ok {
		return fmt.Errorf("lock: required service %q (kv) not registered", "kv")
	}
	kv, ok := svc.(api.KVService)
	if !ok {
		return fmt.Errorf("lock: service %q does not implement api.KVService", "kv")
	}
	p.kv = kv
	return k.Registry().Provide("lock", p)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return api.Health{Status: "ok"} }

var _ api.Plugin = (*Plugin)(nil)
var _ api.LockService = (*Plugin)(nil)

func lockKey(key string) string { return keyPrefix + key }

func (p *Plugin) currentExpiry(ctx context.Context, key string) (time.Time, bool, error) {
	val, ok, err := p.kv.Get(ctx, lockKey(key))
	if err != nil {
		return time.Time{}, false, err
	}
	if !ok {
		return time.Time{}, false, nil
	}
	exp, err := time.Parse(time.RFC3339Nano, string(val))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("lock: corrupt expiry for %q: %w", key, err)
	}
	return exp, true, nil
}

// Acquire returns ErrLockAlreadyAcquired immediately if key is already
// held and not yet expired; it does not block or retry.
func (p *Plugin) Acquire(ctx context.Context, key string, ttl time.Duration) (api.LockHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	exp, held, err := p.currentExpiry(ctx, key)
	if err != nil {
		return nil, err
	}
	if held && time.Now().Before(exp) {
		return nil, ErrLockAlreadyAcquired
	}

	newExp := time.Now().Add(ttl)
	if err := p.kv.Put(ctx, lockKey(key), []byte(newExp.Format(time.RFC3339Nano))); err != nil {
		return nil, fmt.Errorf("lock: acquire: %w", err)
	}
	return &handle{p: p, key: key}, nil
}

func (p *Plugin) IsLocked(ctx context.Context, key string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, held, err := p.currentExpiry(ctx, key)
	if err != nil {
		return false, err
	}
	return held && time.Now().Before(exp), nil
}

func (p *Plugin) release(ctx context.Context, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	exp, held, err := p.currentExpiry(ctx, key)
	if err != nil {
		return err
	}
	if !held {
		return ErrLockNotHeld
	}
	if time.Now().After(exp) {
		return ErrLockExpired
	}
	return p.kv.Delete(ctx, lockKey(key))
}

func (p *Plugin) renew(ctx context.Context, key string, ttl time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	exp, held, err := p.currentExpiry(ctx, key)
	if err != nil {
		return err
	}
	if !held {
		return ErrLockNotHeld
	}
	if time.Now().After(exp) {
		return ErrLockExpired
	}
	newExp := time.Now().Add(ttl)
	return p.kv.Put(ctx, lockKey(key), []byte(newExp.Format(time.RFC3339Nano)))
}

// handle is the api.LockHandle returned by Acquire.
type handle struct {
	p   *Plugin
	key string
}

func (h *handle) Release(ctx context.Context) error { return h.p.release(ctx, h.key) }
func (h *handle) Renew(ctx context.Context, ttl time.Duration) error {
	return h.p.renew(ctx, h.key, ttl)
}

var _ api.LockHandle = (*handle)(nil)

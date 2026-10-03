package comparison

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

// VelocityEngine wraps v2's KVService atop the real storage-lsm plugin,
// booted through the same kernel.Boot path production uses (no
// shortcuts) — mirroring the pattern in ../helpers_test.go's bootKV.
type VelocityEngine struct {
	k   *kernel.Kernel
	svc api.KVService
	ctx context.Context
}

// NewVelocityEngine boots storage-lsm (with always_sync so every write is
// fsync'd, for durability parity with the SQLite/BoltDB providers below)
// plus kv, rooted at dir, using the default FsyncFull mode — real
// power-loss survival, at real hardware cost. See NewVelocityEngineFast
// for the SQLite-durability-equivalent variant.
func NewVelocityEngine(dir string) (*VelocityEngine, error) {
	return newVelocityEngine(dir, "full", 0)
}

// NewVelocityEngineFast boots storage-lsm with fsync_mode: "posix" — the
// plain POSIX fsync(2) syscall, matching SQLite's own default
// WAL+synchronous=FULL durability level (survives process/OS crashes, not
// a real power interruption) rather than storage-lsm's stronger default.
// See plugins/storage-lsm's FsyncMode doc comment for why this distinction
// exists and matters for a fair comparison: an earlier version of this
// benchmark compared NewVelocityEngine (real power-loss survival) against
// SQLite's default (which does NOT survive real power loss on Darwin) and
// reported a 264x gap that was actually measuring two different
// guarantees, not two implementations of the same one.
func NewVelocityEngineFast(dir string) (*VelocityEngine, error) {
	return newVelocityEngine(dir, "posix", 0)
}

// NewVelocityEngineAsync boots storage-lsm in the commit-coalescing mode
// (fsync_mode: "posix", always_sync: false, commit_interval: 1ms): every
// Put returns at in-memory staging speed and one background fsync per
// millisecond durably covers everything staged in that window (bounded
// staleness — at most 1ms of writes can be lost on a power failure, the
// same class of guarantee as Redis AOF everysec or PostgreSQL
// synchronous_commit=off). This is the mode that answers "what does
// Velocity cost when I don't need per-write durability latency" — it is
// NOT a durability-matched comparison against always_sync engines, and
// the RESULTS.md reading must keep those guarantees separate.
func NewVelocityEngineAsync(dir string) (*VelocityEngine, error) {
	return newVelocityEngine(dir, "posix", time.Millisecond)
}

func newVelocityEngine(dir, fsyncMode string, commitInterval time.Duration) (*VelocityEngine, error) {
	alwaysSync := commitInterval == 0
	cfg := map[string]any{
		"dir":         dir,
		"always_sync": alwaysSync,
		"fsync_mode":  fsyncMode,
	}
	if commitInterval > 0 {
		cfg["commit_interval"] = commitInterval.String()
	}
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: cfg},
		{Name: "kv", Enabled: true},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm")}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		return nil, fmt.Errorf("velocity: boot: %w", err)
	}
	svcAny, ok := k.Registry().Lookup("kv")
	if !ok {
		return nil, fmt.Errorf("velocity: kv service not registered")
	}
	svc, ok := svcAny.(api.KVService)
	if !ok {
		return nil, fmt.Errorf("velocity: registered kv service does not implement api.KVService")
	}
	return &VelocityEngine{k: k, svc: svc, ctx: ctx}, nil
}

func (e *VelocityEngine) Put(key, value []byte) error {
	return e.svc.Put(e.ctx, string(key), value)
}

func (e *VelocityEngine) Get(key []byte) ([]byte, bool, error) {
	return e.svc.Get(e.ctx, string(key))
}

func (e *VelocityEngine) Close() error {
	return e.k.Shutdown(e.ctx)
}

var _ KVEngine = (*VelocityEngine)(nil)

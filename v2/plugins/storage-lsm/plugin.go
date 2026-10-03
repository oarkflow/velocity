package lsm

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin registers a durable, WAL-backed, multi-file LSM Engine as the
// kernel's "storage" service — see engine.go's package doc for exactly how
// this compares to v1's full memtable/SSTable/leveled-compaction engine
// (real flush-to-SSTable, real Bloom filters, real compaction; simplified
// in a few stated ways, not a stand-in). Erasure coding, bit-rot scanning,
// and self-healing from v1 (erasure_coding.go/bitrot.go/healing.go)
// operate on object-storage shard layouts that don't exist at this raw
// KV-engine level in v1 either — they live in plugins/erasure instead.
type Plugin struct {
	engine *Engine

	dir                 string
	alwaysSync          bool
	fsyncMode           FsyncMode
	commitInterval      time.Duration
	checkpointEvery     time.Duration
	reapEvery           time.Duration
	flushThresholdBytes int64
	compactionThreshold int

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup

	mu     sync.RWMutex
	health api.Health
}

// New constructs the plugin. Configuration (data directory, fsync policy,
// checkpoint interval) is read from the manifest in Init via
// k.Config().Scoped("storage-lsm"); these constructor args only apply
// when the plugin is built directly (e.g. by tests) without a kernel.
func New() *Plugin {
	return &Plugin{
		dir:                 "",
		alwaysSync:          false,
		checkpointEvery:     30 * time.Second,
		reapEvery:           30 * time.Second,
		flushThresholdBytes: 4 << 20,
		compactionThreshold: 4,
		stopCh:              make(chan struct{}),
		health:              api.Health{Status: "down", Detail: "not started"},
	}
}

func (p *Plugin) Name() string           { return "storage-lsm" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	cfg := k.Config().Scoped(p.Name())
	p.dir = cfg.String("dir", "")
	if p.dir == "" {
		dir, err := os.MkdirTemp("", "velocity-lsm-*")
		if err != nil {
			return err
		}
		p.dir = dir
	}
	p.alwaysSync = cfg.Bool("always_sync", false)
	// fsync_mode: "full" (default) = os.File.Sync(), which is
	// fcntl(F_FULLFSYNC) on Darwin — survives real power loss, at real
	// hardware cost (measured ~1.5-2.5ms/call on this project's dev
	// machine). "posix"/"fast" = the plain POSIX fsync(2) syscall directly
	// — matches SQLite's (and most databases') actual default durability
	// level: survives process/OS crashes, not a real power interruption.
	// See FsyncMode's doc comment in wal.go for the full explanation and
	// why this distinction exists at all (a real benchmark investigation,
	// not a guess).
	p.fsyncMode = ParseFsyncMode(cfg.String("fsync_mode", "full"))
	// commit_interval: bounded-staleness background commit. When set
	// (e.g. "1ms"), staged writes are fsynced at least this often even
	// with always_sync: false — one fsync covers every write staged in
	// the window instead of one fsync per write, with at most one
	// interval of writes lost on a power failure (the same class of
	// guarantee as Redis AOF everysec / PostgreSQL synchronous_commit=off).
	// 0 (default) = original behavior: sync only on write wait or flush.
	p.commitInterval = cfg.Duration("commit_interval", 0)
	p.checkpointEvery = cfg.Duration("checkpoint_interval", 30*time.Second)
	p.reapEvery = cfg.Duration("reap_interval", 30*time.Second)
	p.flushThresholdBytes = int64(cfg.Int("flush_threshold_bytes", 4<<20))
	p.compactionThreshold = cfg.Int("compaction_threshold", 4)

	engine, err := Open(p.dir, p.alwaysSync,
		WithFlushThreshold(p.flushThresholdBytes),
		WithCompactionThreshold(p.compactionThreshold),
		WithFsyncMode(p.fsyncMode),
		WithCommitInterval(p.commitInterval),
	)
	if err != nil {
		p.setHealth("down", err.Error())
		return err
	}
	p.engine = engine

	if err := k.Registry().Provide("storage", p.engine); err != nil {
		return err
	}
	p.setHealth("ok", "opened at "+p.dir)
	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	p.wg.Add(1)
	go p.loop()
	return nil
}

func (p *Plugin) loop() {
	defer p.wg.Done()
	checkpointT := time.NewTicker(p.checkpointEvery)
	reapT := time.NewTicker(p.reapEvery)
	defer checkpointT.Stop()
	defer reapT.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-checkpointT.C:
			if err := p.engine.Checkpoint(context.Background()); err != nil {
				p.setHealth("degraded", "checkpoint failed: "+err.Error())
			} else {
				p.setHealth("ok", "last checkpoint succeeded")
			}
		case <-reapT.C:
			p.engine.reapExpired()
		}
	}
}

func (p *Plugin) Stop(ctx context.Context) error {
	p.stopOnce.Do(func() { close(p.stopCh) })
	p.wg.Wait()
	if p.engine == nil {
		return nil
	}
	return p.engine.Close()
}

func (p *Plugin) Health() api.Health {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.health
}

func (p *Plugin) setHealth(status, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.health = api.Health{Status: status, Detail: detail}
}

var _ api.Plugin = (*Plugin)(nil)

// Package erasure provides Reed-Solomon-style erasure-coded shard storage
// with bit-rot detection and background self-healing, ported from v1's
// erasure_coding.go/bitrot.go/healing.go. It is a standalone, optional
// plugin: v2's storage-lsm engine deliberately does not include this (see
// its own package doc), since in v1 it operated on object-storage shard
// layouts, not the raw KV engine.
//
// Integration sketch for a future pass (not done here): an object plugin
// wanting erasure-coded durability for large bodies would call
// Encode/StoreShards on this plugin's ShardStore instead of storing the
// raw body directly via its own StorageBackend, then ReadShards/
// VerifyShards/HealShards in place of a plain Get. That wiring is a
// separate, larger integration task; this plugin's own capability is
// complete and independently useful without it (e.g. for erasure-coding
// arbitrary blobs a caller manages directly).
package erasure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// shardMeta is persisted per shard-set id so ReadShards/VerifyShards/
// HealShards don't need the original data length or config passed back
// in by the caller.
type shardMeta struct {
	OriginalSize int      `json:"original_size"`
	DataShards   int      `json:"data_shards"`
	ParityShards int      `json:"parity_shards"`
	ShardHashes  []string `json:"shard_hashes"`
}

// Plugin registers a ShardStore as the kernel's "erasure" service.
type Plugin struct {
	storageDep string
	config     Config
	scanEvery  time.Duration

	storage api.StorageBackend
	codec   *Codec
	logger  api.Logger

	mu  sync.Mutex
	ids map[string]struct{} // known shard-set ids, for the background scan loop

	stopCh chan struct{}
	wg     sync.WaitGroup

	health api.Health
}

// NewPlugin constructs the plugin. storageDep selects which storage
// plugin Name() to wait on for boot ordering (default "storage-lsm");
// the actual StorageBackend is always looked up under the fixed service
// name "storage".
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{
		storageDep: storageDep,
		config:     DefaultConfig(),
		scanEvery:  6 * time.Hour, // matches v1 healing.go's default heal interval
		ids:        make(map[string]struct{}),
		stopCh:     make(chan struct{}),
		health:     api.Health{Status: "down", Detail: "not started"},
	}
}

func (p *Plugin) Name() string           { return "erasure" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.logger = k.Logger()
	cfg := k.Config().Scoped(p.Name())

	dataShards := cfg.Int("data_shards", DefaultConfig().DataShards)
	parityShards := cfg.Int("parity_shards", DefaultConfig().ParityShards)
	p.config = Config{DataShards: dataShards, ParityShards: parityShards}
	p.scanEvery = cfg.Duration("scan_interval", 6*time.Hour)

	codec, err := NewCodec(p.config)
	if err != nil {
		return fmt.Errorf("erasure: %w", err)
	}
	p.codec = codec

	svc, ok := k.Registry().Lookup("storage")
	if !ok {
		return fmt.Errorf("erasure: required service %q (storage) not registered", "storage")
	}
	storage, ok := svc.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("erasure: service %q does not implement api.StorageBackend", "storage")
	}
	p.storage = storage

	if err := k.Registry().Provide("erasure", p); err != nil {
		return err
	}
	p.health = api.Health{Status: "ok"}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	p.wg.Add(1)
	go p.scanLoop(ctx)
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	close(p.stopCh)
	p.wg.Wait()
	return nil
}

func (p *Plugin) Health() api.Health { return p.health }

var _ api.Plugin = (*Plugin)(nil)
var _ api.ShardStore = (*Plugin)(nil)

// scanLoop periodically verifies and self-heals every known shard set,
// mirroring v1 healing.go's "detect then repair" background loop.
func (p *Plugin) scanLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.scanEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.scanAndHealAll(ctx)
		}
	}
}

func (p *Plugin) scanAndHealAll(ctx context.Context) {
	p.mu.Lock()
	ids := make([]string, 0, len(p.ids))
	for id := range p.ids {
		ids = append(ids, id)
	}
	p.mu.Unlock()

	for _, id := range ids {
		ok, corrupt, err := p.VerifyShards(ctx, id)
		if err != nil {
			if p.logger != nil {
				p.logger.Warn("erasure: scan verify failed", "id", id, "err", err)
			}
			continue
		}
		if !ok && len(corrupt) > 0 {
			if err := p.HealShards(ctx, id); err != nil && p.logger != nil {
				p.logger.Error("erasure: scan heal failed", "id", id, "err", err)
			}
		}
	}
}

// --- key scheme ---

func metaKey(id string) []byte { return []byte("erasure/" + id + "/meta") }
func shardKey(id string, i int) []byte {
	return []byte(fmt.Sprintf("erasure/%s/shard/%d", id, i))
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// --- api.ShardStore ---

func (p *Plugin) StoreShards(ctx context.Context, id string, data []byte) error {
	shards, err := p.codec.Encode(data)
	if err != nil {
		return fmt.Errorf("erasure encode failed: %w", err)
	}

	hashes := make([]string, len(shards))
	ops := make([]api.BatchOp, 0, len(shards)+1)
	for i, shard := range shards {
		hashes[i] = hashOf(shard)
		ops = append(ops, api.BatchOp{Entry: api.Entry{Key: shardKey(id, i), Value: shard}})
	}

	meta := shardMeta{
		OriginalSize: len(data),
		DataShards:   p.config.DataShards,
		ParityShards: p.config.ParityShards,
		ShardHashes:  hashes,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("erasure: marshal metadata: %w", err)
	}
	ops = append(ops, api.BatchOp{Entry: api.Entry{Key: metaKey(id), Value: metaBytes}})

	if err := p.storage.Batch(ctx, ops); err != nil {
		return fmt.Errorf("erasure: store shards: %w", err)
	}

	p.mu.Lock()
	p.ids[id] = struct{}{}
	p.mu.Unlock()
	return nil
}

func (p *Plugin) loadMeta(ctx context.Context, id string) (shardMeta, error) {
	var meta shardMeta
	raw, ok, err := p.storage.Get(ctx, metaKey(id))
	if err != nil {
		return meta, err
	}
	if !ok {
		return meta, fmt.Errorf("erasure: shard set %q not found", id)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return meta, fmt.Errorf("erasure: unmarshal metadata: %w", err)
	}
	return meta, nil
}

// readVerifiedShards reads every shard for id, nil-ing out any that are
// missing or whose content hash doesn't match the persisted metadata.
func (p *Plugin) readVerifiedShards(ctx context.Context, id string, meta shardMeta) ([][]byte, []int) {
	total := meta.DataShards + meta.ParityShards
	shards := make([][]byte, total)
	var corrupt []int
	for i := 0; i < total; i++ {
		raw, ok, err := p.storage.Get(ctx, shardKey(id, i))
		if err != nil || !ok {
			corrupt = append(corrupt, i)
			continue
		}
		if hashOf(raw) != meta.ShardHashes[i] {
			corrupt = append(corrupt, i)
			continue
		}
		shards[i] = raw
	}
	return shards, corrupt
}

func (p *Plugin) ReadShards(ctx context.Context, id string) ([]byte, error) {
	meta, err := p.loadMeta(ctx, id)
	if err != nil {
		return nil, err
	}
	shards, _ := p.readVerifiedShards(ctx, id, meta)

	codec := p.codec
	if meta.DataShards != p.config.DataShards || meta.ParityShards != p.config.ParityShards {
		codec, err = NewCodec(Config{DataShards: meta.DataShards, ParityShards: meta.ParityShards})
		if err != nil {
			return nil, err
		}
	}
	return codec.Decode(shards, meta.OriginalSize)
}

func (p *Plugin) VerifyShards(ctx context.Context, id string) (bool, []int, error) {
	meta, err := p.loadMeta(ctx, id)
	if err != nil {
		return false, nil, err
	}
	_, corrupt := p.readVerifiedShards(ctx, id, meta)
	return len(corrupt) == 0, corrupt, nil
}

func (p *Plugin) HealShards(ctx context.Context, id string) error {
	meta, err := p.loadMeta(ctx, id)
	if err != nil {
		return err
	}
	shards, corrupt := p.readVerifiedShards(ctx, id, meta)
	if len(corrupt) == 0 {
		return nil
	}

	codec := p.codec
	if meta.DataShards != p.config.DataShards || meta.ParityShards != p.config.ParityShards {
		codec, err = NewCodec(Config{DataShards: meta.DataShards, ParityShards: meta.ParityShards})
		if err != nil {
			return err
		}
	}

	original, err := codec.Decode(shards, meta.OriginalSize)
	if err != nil {
		return fmt.Errorf("erasure: cannot reconstruct for heal: %w", err)
	}
	newShards, err := codec.Encode(original)
	if err != nil {
		return fmt.Errorf("erasure: re-encode failed during heal: %w", err)
	}

	ops := make([]api.BatchOp, 0, len(corrupt))
	newHashes := append([]string(nil), meta.ShardHashes...)
	for _, idx := range corrupt {
		ops = append(ops, api.BatchOp{Entry: api.Entry{Key: shardKey(id, idx), Value: newShards[idx]}})
		newHashes[idx] = hashOf(newShards[idx])
	}
	meta.ShardHashes = newHashes
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	ops = append(ops, api.BatchOp{Entry: api.Entry{Key: metaKey(id), Value: metaBytes}})

	return p.storage.Batch(ctx, ops)
}

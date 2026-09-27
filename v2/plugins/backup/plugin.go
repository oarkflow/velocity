// Package backup implements Velocity v2's backup/restore plugin, closing
// a gap found when auditing v2 against v1: v1's backup.go/backup_security.go
// had HMAC-signed Backup/Restore/Export/Import with tamper rejection, and
// v2 initially shipped with none of that. See format.go for the on-wire
// stream format and its HMAC-signing scheme.
package backup

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin registers "backup" (api.BackupService) atop a StorageBackend
// looked up from the registry. It uses its own HMAC key (config
// "hmac_key"), independent of the crypto plugin, so a backup taken today
// stays restorable even if the crypto plugin's configuration changes
// later — a backup's integrity key and the data's encryption key are
// different concerns.
type Plugin struct {
	storageDep string

	storage api.StorageBackend
	hmacKey []byte
	log     api.Logger

	mu     sync.RWMutex
	health api.Health
}

// NewPlugin constructs the plugin. storageDep names the plugin whose
// Dependencies()-graph position this plugin must boot after; storageDep
// empty defaults to "storage-lsm". The actual StorageBackend is always
// looked up via the fixed service name "storage", regardless of which
// concrete plugin provides it.
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{
		storageDep: storageDep,
		health:     api.Health{Status: "down", Detail: "not started"},
	}
}

func (p *Plugin) Name() string           { return "backup" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()
	cfg := k.Config().Scoped(p.Name())

	storageSvc := k.Registry().MustLookup("storage")
	storage, ok := storageSvc.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("backup: service %q does not implement api.StorageBackend", "storage")
	}
	p.storage = storage

	keyHex := cfg.String("hmac_key", "")
	if keyHex == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("backup: generating ephemeral hmac key: %w", err)
		}
		p.hmacKey = key
		p.log.Warn("backup: no \"hmac_key\" configured — generated a random ephemeral key for this process only; backups made with it cannot be verified/restored after restart unless you persist it. Set config.hmac_key for a real deployment.")
	} else {
		p.hmacKey = []byte(keyHex)
	}

	if err := k.Registry().Provide("backup", p); err != nil {
		return err
	}
	p.setHealth("ok", "ready")
	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

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
var _ api.BackupService = (*Plugin)(nil)

// Backup writes every key in the storage backend to w, signed with this
// plugin's HMAC key. Equivalent to Export with an empty prefix.
func (p *Plugin) Backup(ctx context.Context, w io.Writer) error {
	return p.export(ctx, w, nil)
}

// Export writes every key with the given prefix to w, signed with this
// plugin's HMAC key.
func (p *Plugin) Export(ctx context.Context, w io.Writer, prefix string) error {
	return p.export(ctx, w, []byte(prefix))
}

func (p *Plugin) export(ctx context.Context, w io.Writer, prefix []byte) error {
	it, err := p.storage.Scan(ctx, prefix)
	if err != nil {
		return fmt.Errorf("backup: scan: %w", err)
	}
	defer it.Close()

	var recs []record
	for it.Next() {
		// Copy: iterators are free to reuse their internal buffers across
		// Next() calls, and we hold onto these bytes past the loop.
		k := append([]byte(nil), it.Key()...)
		v := append([]byte(nil), it.Value()...)
		recs = append(recs, record{key: k, value: v})
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("backup: iterate: %w", err)
	}

	if err := encode(w, p.hmacKey, recs); err != nil {
		return fmt.Errorf("backup: encode: %w", err)
	}
	return nil
}

// Restore verifies r's signature, and only on success replaces the
// storage backend's contents with what it decodes. Equivalent to Import
// after first clearing every existing key — full restores are a
// deliberately destructive operation, matching v1's disaster-recovery
// semantics: Restore reconstructs the backend to exactly the backed-up
// state.
func (p *Plugin) Restore(ctx context.Context, r io.Reader) error {
	recs, err := decode(r, p.hmacKey)
	if err != nil {
		return err // ErrTampered / ErrTruncated / bad-magic, unwrapped so callers can errors.Is against them
	}

	// Clear existing keys first (full restore), then apply — still only
	// after decode() has already verified the incoming stream above, so a
	// tampered Restore never reaches this point at all.
	if err := p.clearAll(ctx); err != nil {
		return fmt.Errorf("backup: clearing existing keys before restore: %w", err)
	}
	return p.apply(ctx, recs)
}

// Import applies recs on top of whatever already exists (no clearing) —
// the partial/incremental counterpart to Export, for restoring a subset
// of keys without disturbing the rest of the keyspace.
func (p *Plugin) Import(ctx context.Context, r io.Reader) error {
	recs, err := decode(r, p.hmacKey)
	if err != nil {
		return err
	}
	return p.apply(ctx, recs)
}

func (p *Plugin) apply(ctx context.Context, recs []record) error {
	if len(recs) == 0 {
		return nil
	}
	ops := make([]api.BatchOp, 0, len(recs))
	for _, rec := range recs {
		ops = append(ops, api.BatchOp{Entry: api.Entry{Key: rec.key, Value: rec.value}})
	}
	if err := p.storage.Batch(ctx, ops); err != nil {
		return fmt.Errorf("backup: applying restored records: %w", err)
	}
	return nil
}

func (p *Plugin) clearAll(ctx context.Context) error {
	it, err := p.storage.Scan(ctx, nil)
	if err != nil {
		return err
	}
	defer it.Close()

	var ops []api.BatchOp
	for it.Next() {
		k := append([]byte(nil), it.Key()...)
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: k}})
	}
	if err := it.Err(); err != nil {
		return err
	}
	if len(ops) == 0 {
		return nil
	}
	return p.storage.Batch(ctx, ops)
}

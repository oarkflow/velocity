// Package secret implements Velocity v2's secrets-management plugin,
// ported from v1's secrets_hardening.go: structured, versioned records
// whose values are sealed via a looked-up api.CryptoProvider and checksum
// verified on read, never stored as plaintext. It registers under the
// fixed service name "secret", built on top of whatever "storage" and
// "crypto" plugins are enabled in the manifest.
//
// v1's Shamir-backed master-key split/combine (master_key_manager.go) is
// intentionally NOT ported in this pass — this plugin only consumes an
// already-constructed api.CryptoProvider from the registry. A future
// admin-facing plugin can layer Shamir-based master-key rotation on top
// by driving whichever crypto plugin's underlying key material, without
// this plugin needing to change.
package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "secret"

// record is the on-disk shape for one sealed secret version.
type record struct {
	Version   int       `json:"version"`
	Sealed    []byte    `json:"sealed"`
	Checksum  string    `json:"checksum"` // sha256 hex of the plaintext, verified on read
	CreatedAt time.Time `json:"created_at"`
}

// Plugin implements api.Plugin and api.SecretService.
type Plugin struct {
	storageDep string
	cryptoDep  string

	storage api.StorageBackend
	crypto  api.CryptoProvider
	events  api.EventBus
	log     api.Logger
	health  api.Health

	// mu serializes Set/Rotate per plugin instance. Coarse-grained on
	// purpose: secrets writes are low-frequency compared to KV/object
	// traffic, and this avoids a lost-update race between concurrent
	// Set/Rotate calls on the same or different names incrementing the
	// same latest-version pointer.
	mu sync.Mutex
}

// NewPlugin constructs the secret plugin. storageDep/cryptoDep name the
// concrete plugins to depend on for boot ordering (Registry lookups
// always use the fixed service names "storage"/"crypto" regardless of
// which concrete plugin provided them). Empty strings default to
// "storage-lsm" and "crypto-xchacha".
func NewPlugin(storageDep, cryptoDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	if cryptoDep == "" {
		cryptoDep = "crypto-xchacha"
	}
	return &Plugin{storageDep: storageDep, cryptoDep: cryptoDep}
}

func (p *Plugin) Name() string           { return pluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep, p.cryptoDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	p.crypto = k.Registry().MustLookup("crypto").(api.CryptoProvider)
	p.events = k.Events()
	p.log = k.Logger()

	if err := k.Registry().Provide("secret", p); err != nil {
		return err
	}
	p.health = api.Health{Status: "ok"}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return p.health }

var _ api.Plugin = (*Plugin)(nil)
var _ api.SecretService = (*Plugin)(nil)

// --- api.SecretService ---

func (p *Plugin) Set(ctx context.Context, name string, value []byte) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("%s: secret name is required", pluginName)
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	latest, err := p.latestVersion(ctx, name)
	if err != nil {
		latest = 0 // not found yet — this Set creates version 1
	}
	version := latest + 1

	if err := p.putVersion(ctx, name, version, value); err != nil {
		return 0, err
	}
	if err := p.storage.Put(ctx, api.Entry{Key: latestKey(name), Value: []byte(strconv.Itoa(version))}); err != nil {
		return 0, fmt.Errorf("%s: updating latest pointer for %q: %w", pluginName, name, err)
	}

	p.events.Publish(ctx, api.Event{Topic: api.TopicSecretSet, Source: pluginName, Payload: name})
	return version, nil
}

func (p *Plugin) Get(ctx context.Context, name string, version int) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("%s: secret name is required", pluginName)
	}
	if version == 0 {
		v, err := p.latestVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		version = v
	}
	plaintext, err := p.getVersionPlain(ctx, name, version)
	if err != nil {
		return nil, err
	}
	p.events.Publish(ctx, api.Event{Topic: api.TopicSecretAccess, Source: pluginName, Payload: name})
	return plaintext, nil
}

func (p *Plugin) Versions(ctx context.Context, name string) ([]api.SecretVersion, error) {
	it, err := p.storage.Scan(ctx, []byte(versionPrefix(name)))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []api.SecretVersion
	for it.Next() {
		var rec record
		if err := json.Unmarshal(it.Value(), &rec); err != nil {
			return nil, fmt.Errorf("%s: corrupt version record for %q: %w", pluginName, name, err)
		}
		out = append(out, api.SecretVersion{Version: rec.Version, Value: rec.Sealed, CreatedAt: rec.CreatedAt})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Plugin) Delete(ctx context.Context, name string) error {
	it, err := p.storage.Scan(ctx, []byte(versionPrefix(name)))
	if err != nil {
		return err
	}
	var keys [][]byte
	for it.Next() {
		keys = append(keys, append([]byte(nil), it.Key()...))
	}
	closeErr := it.Close()
	if err := it.Err(); err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	ops := make([]api.BatchOp, 0, len(keys)+1)
	for _, key := range keys {
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: key}})
	}
	ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: latestKey(name)}})
	return p.storage.Batch(ctx, ops)
}

// Rotate re-seals the latest version's already-known plaintext under the
// current CryptoProvider (e.g. after the underlying master key changed),
// keeping the same version number and value.
func (p *Plugin) Rotate(ctx context.Context, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	version, err := p.latestVersion(ctx, name)
	if err != nil {
		return err
	}
	plaintext, err := p.getVersionPlain(ctx, name, version)
	if err != nil {
		return err
	}
	if err := p.putVersion(ctx, name, version, plaintext); err != nil {
		return err
	}
	p.events.Publish(ctx, api.Event{Topic: api.TopicSecretRotate, Source: pluginName, Payload: name})
	return nil
}

// --- internals ---

func (p *Plugin) putVersion(ctx context.Context, name string, version int, plaintext []byte) error {
	sealed, err := p.crypto.Encrypt(ctx, plaintext, aad(name, version))
	if err != nil {
		return fmt.Errorf("%s: sealing %q v%d: %w", pluginName, name, version, err)
	}
	sum := sha256.Sum256(plaintext)
	rec := record{Version: version, Sealed: sealed, Checksum: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: versionKey(name, version), Value: data})
}

func (p *Plugin) getVersionPlain(ctx context.Context, name string, version int) ([]byte, error) {
	data, ok, err := p.storage.Get(ctx, versionKey(name, version))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s: %q version %d not found", pluginName, name, version)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%s: corrupt version record for %q: %w", pluginName, name, err)
	}
	plaintext, err := p.crypto.Decrypt(ctx, rec.Sealed, aad(name, version))
	if err != nil {
		return nil, fmt.Errorf("%s: unsealing %q v%d: %w", pluginName, name, version, err)
	}
	sum := sha256.Sum256(plaintext)
	if hex.EncodeToString(sum[:]) != rec.Checksum {
		return nil, fmt.Errorf("%s: %q v%d failed checksum verification — possible tampering or corruption", pluginName, name, version)
	}
	return plaintext, nil
}

func (p *Plugin) latestVersion(ctx context.Context, name string) (int, error) {
	data, ok, err := p.storage.Get(ctx, latestKey(name))
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("%s: %q not found", pluginName, name)
	}
	v, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("%s: corrupt latest-version pointer for %q: %w", pluginName, name, err)
	}
	return v, nil
}

func versionKey(name string, version int) []byte {
	return []byte(fmt.Sprintf("secret/%s/v/%d", name, version))
}

func versionPrefix(name string) string {
	return fmt.Sprintf("secret/%s/v/", name)
}

func latestKey(name string) []byte {
	return []byte(fmt.Sprintf("secret/%s/latest", name))
}

func aad(name string, version int) []byte {
	return []byte(fmt.Sprintf("secret:%s:%d", name, version))
}

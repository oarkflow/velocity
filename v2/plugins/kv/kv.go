// Package kv implements the Velocity v2 "kv" plugin: api.KVService built as
// a thin layer over whatever api.StorageBackend is registered under the
// service name "storage" (provided by storage-lsm or storage-mem).
//
// Ported/adapted from v1's velocity.go (Put/Get/GetInto/Exists/Delete/
// Incr/Decr/Keys/KeysPage/Scan) and kv_api_regression_test.go, with the
// direct memtable/SSTable access replaced by calls through
// api.StorageBackend so this plugin works unchanged against any backend.
package kv

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.KVService under.
const ServiceName = "kv"

// ErrEmptyKey mirrors v1's guard against empty keys (v1 had a real
// &key[0] panic bug on empty keys, fixed shortly before this rework;
// reject it explicitly here instead).
var ErrEmptyKey = errors.New("kv: key must not be empty")

// Plugin implements api.Plugin and api.KVService.
type Plugin struct {
	storageDep string

	storage api.StorageBackend
	events  api.EventBus
	log     api.Logger

	// crypto is non-nil only when this plugin's "encrypt" config is true
	// AND a CryptoProvider is registered under "crypto" — see Init. When
	// nil, seal/unseal are no-ops, so encryption adds zero behavior change
	// unless explicitly turned on. Only VALUES are encrypted, never keys:
	// encrypting keys would break prefix-based Scan/Keys entirely and is
	// out of scope for this pass.
	crypto api.CryptoProvider

	// incrMu is a coarse global lock guarding Incr's read-modify-write.
	// Correctness over concurrency granularity for this first pass; a
	// deployment with hot counters should shard this by key hash instead.
	incrMu sync.Mutex

	// watchMu guards activeWatches, an internal count exposed only for
	// tests to assert Watch/Close doesn't leak subscriptions.
	watchMu       sync.Mutex
	activeWatches int
}

// New constructs the kv plugin. storageDep names the storage plugin this
// one depends on for boot ordering (NOT the service-lookup name, which is
// always the fixed "storage"); it defaults to "storage-lsm" when empty.
func New(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep}
}

func (p *Plugin) Name() string           { return "kv" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

// OptionalDependencies lists "crypto": if a crypto plugin is enabled in
// the manifest, the kernel Inits it before this one so the optional
// Registry.Lookup("crypto") below is never a boot-order race — same
// pattern as the object plugin's optional "erasure" dependency.
func (p *Plugin) OptionalDependencies() []string { return []string{"crypto"} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	p.events = k.Events()
	p.log = k.Logger()

	if k.Config().Scoped(p.Name()).Bool("encrypt", false) {
		svc, ok := k.Registry().Lookup("crypto")
		if !ok {
			return fmt.Errorf("kv: config \"encrypt\" is true but no \"crypto\" service is registered — enable a crypto-* plugin, or set encrypt to false")
		}
		cp, ok := svc.(api.CryptoProvider)
		if !ok {
			return fmt.Errorf("kv: service registered under \"crypto\" does not implement api.CryptoProvider")
		}
		p.crypto = cp
	}

	return k.Registry().Provide(ServiceName, api.KVService(p))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	return api.Health{Status: "ok"}
}

func (p *Plugin) Put(ctx context.Context, key string, value []byte) error {
	return p.PutWithTTL(ctx, key, value, 0)
}

func (p *Plugin) PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return ErrEmptyKey
	}
	sealed, err := p.seal(ctx, key, value)
	if err != nil {
		return err
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(key), Value: sealed, TTL: ttl}); err != nil {
		return err
	}
	// The event reports the plaintext size (len(value), not len(sealed))
	// since that's the semantically meaningful quantity for observers —
	// ciphertext overhead (nonce/tag bytes) is an encryption implementation
	// detail, not content the caller cares about.
	p.publish(ctx, api.TopicKVPut, map[string]any{"key": key, "size": len(value)})
	return nil
}

func (p *Plugin) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if key == "" {
		return nil, false, ErrEmptyKey
	}
	v, ok, err := p.storage.Get(ctx, []byte(key))
	if err != nil || !ok {
		return v, ok, err
	}
	plain, err := p.unseal(ctx, key, v)
	if err != nil {
		return nil, false, err
	}
	return plain, true, nil
}

// seal encrypts value for storage under key (using the key itself as AAD,
// so a ciphertext can never be silently swapped onto a different key —
// same convention plugins/secret uses). A no-op when encryption isn't
// enabled (p.crypto == nil).
func (p *Plugin) seal(ctx context.Context, key string, value []byte) ([]byte, error) {
	if p.crypto == nil {
		return value, nil
	}
	sealed, err := p.crypto.Encrypt(ctx, value, kvAAD(key))
	if err != nil {
		return nil, fmt.Errorf("kv: sealing %q: %w", key, err)
	}
	return sealed, nil
}

// unseal is seal's inverse; also a no-op when encryption isn't enabled.
func (p *Plugin) unseal(ctx context.Context, key string, value []byte) ([]byte, error) {
	if p.crypto == nil {
		return value, nil
	}
	plain, err := p.crypto.Decrypt(ctx, value, kvAAD(key))
	if err != nil {
		return nil, fmt.Errorf("kv: unsealing %q: %w", key, err)
	}
	return plain, nil
}

func kvAAD(key string) []byte {
	return []byte("kv:" + key)
}

func (p *Plugin) Delete(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	if err := p.storage.Delete(ctx, []byte(key)); err != nil {
		return err
	}
	p.publish(ctx, api.TopicKVDelete, map[string]any{"key": key})
	return nil
}

func (p *Plugin) Exists(ctx context.Context, key string) (bool, error) {
	_, ok, err := p.Get(ctx, key)
	return ok, err
}

// Incr performs a read-modify-write increment. See incrMu doc comment for
// the concurrency-granularity tradeoff.
func (p *Plugin) Incr(ctx context.Context, key string, delta int64) (int64, error) {
	if key == "" {
		return 0, ErrEmptyKey
	}
	p.incrMu.Lock()
	defer p.incrMu.Unlock()

	var cur int64
	if v, ok, err := p.storage.Get(ctx, []byte(key)); err != nil {
		return 0, err
	} else if ok {
		plain, err := p.unseal(ctx, key, v)
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseInt(string(plain), 10, 64)
		if err != nil {
			return 0, errors.New("kv: existing value is not an integer, cannot Incr")
		}
		cur = n
	}

	next := cur + delta
	encoded := strconv.FormatInt(next, 10)
	sealed, err := p.seal(ctx, key, []byte(encoded))
	if err != nil {
		return 0, err
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(key), Value: sealed}); err != nil {
		return 0, err
	}
	p.publish(ctx, api.TopicKVPut, map[string]any{"key": key, "size": len(encoded)})
	return next, nil
}

// Keys returns every key matching pattern (path.Match glob syntax). This
// is an O(n) full scan — intended for small keyspaces and tooling. Scan is
// the paginated, production-safe path for large keyspaces.
func (p *Plugin) Keys(ctx context.Context, pattern string) ([]string, error) {
	it, err := p.storage.Scan(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []string
	for it.Next() {
		k := string(it.Key())
		if pattern == "" || pattern == "*" {
			out = append(out, k)
			continue
		}
		matched, merr := path.Match(pattern, k)
		if merr != nil {
			return nil, merr
		}
		if matched {
			out = append(out, k)
		}
	}
	return out, it.Err()
}

// Scan returns up to limit items with the given prefix, resuming after
// cursor (the last key seen in the previous page; empty starts at the
// beginning). nextCursor is empty when there are no more items.
func (p *Plugin) Scan(ctx context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
	it, err := p.storage.Scan(ctx, []byte(prefix))
	if err != nil {
		return nil, "", err
	}
	defer it.Close()

	items := make(map[string][]byte)
	nextCursor := ""
	resumed := cursor == ""
	count := 0

	for it.Next() {
		k := string(it.Key())
		if !resumed {
			if k != cursor {
				continue
			}
			// cursor names the next key to return (set as nextCursor by
			// the previous page right before it would have exceeded its
			// limit), not the last key already returned — so once found,
			// fall through and process it in this page instead of
			// skipping it.
			resumed = true
		}
		if limit > 0 && count >= limit {
			nextCursor = k
			break
		}
		v := make([]byte, len(it.Value()))
		copy(v, it.Value())
		plain, err := p.unseal(ctx, k, v)
		if err != nil {
			return nil, "", err
		}
		items[k] = plain
		count++
	}
	if err := it.Err(); err != nil {
		return nil, "", err
	}
	return items, nextCursor, nil
}

func (p *Plugin) publish(ctx context.Context, topic string, payload any) {
	if p.events == nil {
		return
	}
	p.events.Publish(ctx, api.Event{Topic: topic, Source: p.Name(), Payload: payload})
}

// watchHandle implements api.WatchHandle for a single Watch subscription.
type watchHandle struct {
	closeOnce func()
}

func (h *watchHandle) Close() { h.closeOnce() }

// Watch implements api.Watchable: it subscribes to this plugin's own
// TopicKVPut/TopicKVDelete publications (the same ones every Put/Delete
// already emits) and forwards only the events whose key has the given
// prefix, as api.ChangeEvent, until ctx is cancelled or the returned
// WatchHandle is closed. ActiveWatches (test-only, see kv_test.go) lets
// tests assert Close doesn't leak the subscription or the channel.
func (p *Plugin) Watch(ctx context.Context, prefix string) (<-chan api.ChangeEvent, api.WatchHandle, error) {
	if p.events == nil {
		return nil, nil, errors.New("kv: no event bus available to watch")
	}

	out := make(chan api.ChangeEvent, 16)
	var closeOnce sync.Once
	var sub api.Subscription

	deliver := func(ctx context.Context, ev api.Event) {
		m, _ := ev.Payload.(map[string]any)
		key, _ := m["key"].(string)
		if !strings.HasPrefix(key, prefix) {
			return
		}
		ce := api.ChangeEvent{Topic: ev.Topic, Key: key, Deleted: ev.Topic == api.TopicKVDelete}
		select {
		case out <- ce:
		case <-ctx.Done():
		}
	}

	putSub := p.events.Subscribe(api.TopicKVPut, deliver)
	delSub := p.events.Subscribe(api.TopicKVDelete, deliver)
	_ = sub // placeholder to keep symmetry with object plugin's single-sub variant if refactored later

	p.watchMu.Lock()
	p.activeWatches++
	p.watchMu.Unlock()

	closeFn := func() {
		closeOnce.Do(func() {
			putSub.Unsubscribe()
			delSub.Unsubscribe()
			close(out)
			p.watchMu.Lock()
			p.activeWatches--
			p.watchMu.Unlock()
		})
	}

	// Auto-close if the caller's context is cancelled without an explicit
	// Close call.
	go func() {
		<-ctx.Done()
		closeFn()
	}()

	return out, &watchHandle{closeOnce: closeFn}, nil
}

// ActiveWatches reports the number of currently-open Watch subscriptions.
// Exported for tests only (both in-package and, since it's a plain
// method on an exported type, from other packages that want to assert on
// it without needing to import internals).
func (p *Plugin) ActiveWatches() int {
	p.watchMu.Lock()
	defer p.watchMu.Unlock()
	return p.activeWatches
}

var (
	_ api.Plugin    = (*Plugin)(nil)
	_ api.KVService = (*Plugin)(nil)
	_ api.Watchable = (*Plugin)(nil)
)

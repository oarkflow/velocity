package secret

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"

	"github.com/oarkflow/velocity/v2/api"
)

// --- minimal in-memory StorageBackend stub, kept local to this test so it
// doesn't depend on the storage-mem plugin package (built by a parallel
// agent and may not exist at test time). ---

type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}

func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}

func (m *memBackend) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = op.Entry.Value
		}
	}
	return nil
}

func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, string(prefix)) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &memIterator{backend: m, keys: keys, idx: -1}, nil
}

func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string][]byte, len(m.data))
	for k, v := range m.data {
		cp[k] = v
	}
	return &memSnapshot{data: cp}, nil
}

func (m *memBackend) Close() error { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool { it.idx++; return it.idx < len(it.keys) }
func (it *memIterator) Key() []byte {
	return []byte(it.keys[it.idx])
}
func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}
func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

type memSnapshot struct{ data map[string][]byte }

func (s *memSnapshot) Get(key []byte) ([]byte, bool, error) {
	v, ok := s.data[string(key)]
	return v, ok, nil
}
func (s *memSnapshot) Release() {}

var _ api.StorageBackend = (*memBackend)(nil)

// --- stub kernel wiring, mirroring the pattern used by crypto-xchacha's
// own tests ---

type stubEventBus struct {
	mu     sync.Mutex
	events []api.Event
}

func (b *stubEventBus) Publish(ctx context.Context, ev api.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, ev)
}
func (b *stubEventBus) Subscribe(topic string, h api.Handler) api.Subscription { return stubSub{} }

type stubSub struct{}

func (stubSub) Unsubscribe() {}

type stubRegistry struct{ services map[string]any }

func (r *stubRegistry) Provide(name string, svc any) error {
	if _, exists := r.services[name]; exists {
		return nil
	}
	r.services[name] = svc
	return nil
}
func (r *stubRegistry) Lookup(name string) (any, bool) { s, ok := r.services[name]; return s, ok }
func (r *stubRegistry) MustLookup(name string) any     { return r.services[name] }

type stubConfig struct{}

func (stubConfig) Scoped(string) api.PluginConfig { return stubPluginConfig{} }

type stubPluginConfig struct{}

func (stubPluginConfig) Raw() map[string]any                                  { return nil }
func (stubPluginConfig) String(key, def string) string                        { return def }
func (stubPluginConfig) Int(key string, def int) int                          { return def }
func (stubPluginConfig) Bool(key string, def bool) bool                       { return def }
func (stubPluginConfig) Duration(key string, def time.Duration) time.Duration { return def }

type stubLogger struct{}

func (stubLogger) Debug(string, ...any) {}
func (stubLogger) Info(string, ...any)  {}
func (stubLogger) Warn(string, ...any)  {}
func (stubLogger) Error(string, ...any) {}

type stubKernel struct {
	reg *stubRegistry
	bus *stubEventBus
}

func (k stubKernel) Registry() api.Registry     { return k.reg }
func (k stubKernel) Events() api.EventBus       { return k.bus }
func (k stubKernel) Config() api.ConfigProvider { return stubConfig{} }
func (k stubKernel) Logger() api.Logger         { return stubLogger{} }

func newTestKernel(t *testing.T) (stubKernel, *memBackend) {
	t.Helper()
	backend := newMemBackend()
	reg := &stubRegistry{services: map[string]any{}}
	k := stubKernel{reg: reg, bus: &stubEventBus{}}

	cp := cryptoxchacha.New()
	if err := cp.Init(context.Background(), k); err != nil {
		t.Fatalf("crypto Init: %v", err)
	}
	if err := reg.Provide("storage", backend); err != nil {
		t.Fatalf("provide storage: %v", err)
	}
	return k, backend
}

func newSecretPlugin(t *testing.T) (*Plugin, stubKernel) {
	t.Helper()
	k, _ := newTestKernel(t)
	p := NewPlugin("", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("secret Init: %v", err)
	}
	return p, k
}

func TestSetGetRoundTrip(t *testing.T) {
	p, _ := newSecretPlugin(t)
	ctx := context.Background()

	v, err := p.Set(ctx, "db-password", []byte("s3cr3t"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v != 1 {
		t.Fatalf("expected version 1, got %d", v)
	}

	got, err := p.Get(ctx, "db-password", 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("s3cr3t")) {
		t.Fatalf("value mismatch: got %q", got)
	}
}

func TestSetCreatesNewVersions(t *testing.T) {
	p, _ := newSecretPlugin(t)
	ctx := context.Background()

	if _, err := p.Set(ctx, "api-key", []byte("v1val")); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	v2, err := p.Set(ctx, "api-key", []byte("v2val"))
	if err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	if v2 != 2 {
		t.Fatalf("expected version 2, got %d", v2)
	}

	latest, err := p.Get(ctx, "api-key", 0)
	if err != nil || !bytes.Equal(latest, []byte("v2val")) {
		t.Fatalf("expected latest to be v2val, got %q err=%v", latest, err)
	}
	v1, err := p.Get(ctx, "api-key", 1)
	if err != nil || !bytes.Equal(v1, []byte("v1val")) {
		t.Fatalf("expected v1 to still be v1val, got %q err=%v", v1, err)
	}

	versions, err := p.Versions(ctx, "api-key")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
}

func TestDeleteRemovesAllVersions(t *testing.T) {
	p, _ := newSecretPlugin(t)
	ctx := context.Background()
	if _, err := p.Set(ctx, "temp", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := p.Delete(ctx, "temp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Get(ctx, "temp", 0); err == nil {
		t.Fatalf("expected Get to fail after Delete")
	}
}

func TestRotateKeepsValueSameVersion(t *testing.T) {
	p, _ := newSecretPlugin(t)
	ctx := context.Background()
	v, err := p.Set(ctx, "rotating", []byte("stable-value"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := p.Rotate(ctx, "rotating"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	got, err := p.Get(ctx, "rotating", v)
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	if !bytes.Equal(got, []byte("stable-value")) {
		t.Fatalf("value changed after rotate: %q", got)
	}
	versions, _ := p.Versions(ctx, "rotating")
	if len(versions) != 1 {
		t.Fatalf("rotate should not create a new version, got %d versions", len(versions))
	}
}

func TestGetUnknownSecretFails(t *testing.T) {
	p, _ := newSecretPlugin(t)
	if _, err := p.Get(context.Background(), "does-not-exist", 0); err == nil {
		t.Fatalf("expected error for unknown secret")
	}
}

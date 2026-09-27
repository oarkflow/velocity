package transaction

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/secret"
)

// --- minimal, self-contained api.Kernel stub, generic enough to boot real
// kv/secret/crypto-xchacha/transaction plugins for a genuine cross-package
// integration test (not a hand-rolled fake of kv/secret's own behavior). ---

type stubRegistry struct {
	mu       sync.Mutex
	services map[string]any
}

func (r *stubRegistry) Provide(name string, svc any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("already provided: %s", name)
	}
	r.services[name] = svc
	return nil
}
func (r *stubRegistry) Lookup(name string) (any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.services[name]
	return v, ok
}
func (r *stubRegistry) MustLookup(name string) any {
	v, ok := r.Lookup(name)
	if !ok {
		panic("missing service: " + name)
	}
	return v
}

type stubEventBus struct{}

func (stubEventBus) Publish(ctx context.Context, ev api.Event)              {}
func (stubEventBus) Subscribe(topic string, h api.Handler) api.Subscription { return stubSub{} }

type stubSub struct{}

func (stubSub) Unsubscribe() {}

type stubConfig struct{ raw map[string]any }

func (c stubConfig) Scoped(string) api.PluginConfig { return stubPluginConfig{c.raw} }

type stubPluginConfig struct{ raw map[string]any }

func (c stubPluginConfig) String(key, def string) string {
	if v, ok := c.raw[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}
func (c stubPluginConfig) Int(key string, def int) int { return def }
func (c stubPluginConfig) Bool(key string, def bool) bool {
	if v, ok := c.raw[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}
func (c stubPluginConfig) Duration(key string, def time.Duration) time.Duration { return def }
func (c stubPluginConfig) Raw() map[string]any                                  { return c.raw }

type stubLogger struct{}

func (stubLogger) Debug(string, ...any) {}
func (stubLogger) Info(string, ...any)  {}
func (stubLogger) Warn(string, ...any)  {}
func (stubLogger) Error(string, ...any) {}

type stubKernel struct {
	reg *stubRegistry
	cfg map[string]any
}

func (k stubKernel) Registry() api.Registry     { return k.reg }
func (k stubKernel) Events() api.EventBus       { return stubEventBus{} }
func (k stubKernel) Config() api.ConfigProvider { return stubConfig{k.cfg} }
func (k stubKernel) Logger() api.Logger         { return stubLogger{} }

var _ api.Kernel = stubKernel{}

// --- an in-memory StorageBackend whose Batch can be told to fail on a
// specific poison key, WITHOUT applying anything else in that call — this
// is what lets the atomicity test actually prove something, rather than
// merely exercising the happy path. ---

type poisonableBackend struct {
	mu     sync.Mutex
	data   map[string][]byte
	poison string // if set, Batch rejects any call containing this key, before applying ANY op in it
}

func newPoisonableBackend() *poisonableBackend {
	return &poisonableBackend{data: map[string][]byte{}}
}

func (m *poisonableBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *poisonableBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *poisonableBackend) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}
func (m *poisonableBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.poison != "" {
		for _, op := range ops {
			if string(op.Entry.Key) == m.poison {
				return fmt.Errorf("poisonableBackend: refusing entire batch, contains poisoned key %q", m.poison)
			}
		}
	}
	// Validate-then-apply: a real backend validates every op before
	// mutating anything, so a rejected batch never leaves partial state —
	// mirror that here rather than applying-as-we-go.
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = op.Entry.Value
		}
	}
	return nil
}
func (m *poisonableBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	return nil, fmt.Errorf("not implemented in this test stub")
}
func (m *poisonableBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	return nil, fmt.Errorf("not implemented in this test stub")
}
func (m *poisonableBackend) Close() error { return nil }

var _ api.StorageBackend = (*poisonableBackend)(nil)

// setup boots real kv, secret, crypto-xchacha, and transaction plugins
// sharing ONE poisonableBackend instance, via their real Init methods —
// this proves the cross-plugin transaction against the actual plugins,
// not a simulation of them.
func setup(t *testing.T) (*kv.Plugin, *secret.Plugin, *Plugin, *poisonableBackend) {
	t.Helper()
	ctx := context.Background()
	backend := newPoisonableBackend()
	reg := &stubRegistry{services: map[string]any{}}
	k := stubKernel{reg: reg, cfg: map[string]any{}}

	if err := reg.Provide("storage", backend); err != nil {
		t.Fatalf("provide storage: %v", err)
	}

	cp := cryptoxchacha.New()
	if err := cp.Init(ctx, k); err != nil {
		t.Fatalf("crypto Init: %v", err)
	}

	kvp := kv.New("storage-lsm")
	if err := kvp.Init(ctx, k); err != nil {
		t.Fatalf("kv Init: %v", err)
	}

	sp := secret.NewPlugin("storage-lsm", "crypto-xchacha")
	if err := sp.Init(ctx, k); err != nil {
		t.Fatalf("secret Init: %v", err)
	}

	txp := NewPlugin()
	if err := txp.Init(ctx, k); err != nil {
		t.Fatalf("transaction Init: %v", err)
	}

	return kvp, sp, txp, backend
}

func TestCrossPluginTx_CommitAppliesBothWrites(t *testing.T) {
	ctx := context.Background()
	kvp, sp, txp, _ := setup(t)

	tx, err := txp.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := kvp.PutStaged(ctx, tx, "order:1", []byte("pending")); err != nil {
		t.Fatalf("PutStaged: %v", err)
	}
	if _, err := sp.SetStaged(ctx, tx, "order:1:token", []byte("s3cr3t-token")); err != nil {
		t.Fatalf("SetStaged: %v", err)
	}

	// Neither write has taken effect yet — Commit hasn't been called.
	if _, ok, _ := kvp.Get(ctx, "order:1"); ok {
		t.Fatalf("kv write took effect before Commit")
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	v, ok, err := kvp.Get(ctx, "order:1")
	if err != nil || !ok || string(v) != "pending" {
		t.Fatalf("kv Get after commit = %q, %v, %v", v, ok, err)
	}
	secretVal, err := sp.Get(ctx, "order:1:token", 0)
	if err != nil || string(secretVal) != "s3cr3t-token" {
		t.Fatalf("secret Get after commit = %q, %v", secretVal, err)
	}
}

func TestCrossPluginTx_RollbackAppliesNeither(t *testing.T) {
	ctx := context.Background()
	kvp, sp, txp, _ := setup(t)

	tx, err := txp.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := kvp.PutStaged(ctx, tx, "order:2", []byte("pending")); err != nil {
		t.Fatalf("PutStaged: %v", err)
	}
	if _, err := sp.SetStaged(ctx, tx, "order:2:token", []byte("s3cr3t-token")); err != nil {
		t.Fatalf("SetStaged: %v", err)
	}

	tx.Rollback()

	if _, ok, _ := kvp.Get(ctx, "order:2"); ok {
		t.Fatalf("kv write took effect after Rollback")
	}
	if _, err := sp.Get(ctx, "order:2:token", 0); err == nil {
		t.Fatalf("secret write took effect after Rollback")
	}
}

// TestCrossPluginTx_GenuineAtomicityUnderPartialFailure is the most
// important test: it proves Commit is genuinely all-or-nothing, not
// "both succeed in the happy path." A kv write and a secret write are
// staged; the underlying backend is configured to reject the WHOLE batch
// because of a poisoned key belonging to the secret's version record.
// Commit must fail, and — critically — the KV write (which by itself
// would have been perfectly valid) must NOT have taken effect either.
func TestCrossPluginTx_GenuineAtomicityUnderPartialFailure(t *testing.T) {
	ctx := context.Background()
	kvp, sp, txp, backend := setup(t)

	tx, err := txp.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := kvp.PutStaged(ctx, tx, "order:3", []byte("pending")); err != nil {
		t.Fatalf("PutStaged: %v", err)
	}
	if _, err := sp.SetStaged(ctx, tx, "order:3:token", []byte("s3cr3t-token")); err != nil {
		t.Fatalf("SetStaged: %v", err)
	}

	// Poison the secret's version-1 record key so the single underlying
	// Batch call fails entirely.
	backend.mu.Lock()
	backend.poison = "secret/order:3:token/v/1"
	backend.mu.Unlock()

	if err := tx.Commit(ctx); err == nil {
		t.Fatalf("expected Commit to fail due to the poisoned batch, got nil error")
	}

	// The kv write must NOT have taken effect either, even though it was
	// individually valid — this is the actual atomicity proof.
	if _, ok, _ := kvp.Get(ctx, "order:3"); ok {
		t.Fatalf("kv write took effect despite the batch failing — atomicity violated")
	}
	if _, err := sp.Get(ctx, "order:3:token", 0); err == nil {
		t.Fatalf("secret write took effect despite the batch failing — atomicity violated")
	}
}

func TestCrossPluginTx_RefusesMismatchedBackends(t *testing.T) {
	ctx := context.Background()
	kvp, _, txp, _ := setup(t)

	otherBackend := newPoisonableBackend()

	tx, err := txp.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := kvp.PutStaged(ctx, tx, "order:4", []byte("pending")); err != nil {
		t.Fatalf("PutStaged: %v", err)
	}
	// Directly Stage against a DIFFERENT backend instance than kv's own —
	// simulating a second participant that doesn't share kv's storage.
	if err := tx.Stage(otherBackend, []api.BatchOp{{Entry: api.Entry{Key: []byte("x"), Value: []byte("y")}}}); err == nil {
		t.Fatalf("expected Stage to refuse a mismatched backend instance, got nil error")
	}
}

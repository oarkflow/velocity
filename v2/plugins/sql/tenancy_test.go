package sql

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/plugins/kv"
)

// --- minimal, self-contained api.Kernel stub (same shape as
// plugins/transaction/integration_test.go's) so this test boots the REAL
// plugins/kv (with its own real tenant-scoping, not a hand-rolled fake of
// it) as sql's api.KVService — this is what makes the isolation proof
// below meaningful rather than circular. ---

type sqlTenancyStubRegistry struct {
	mu       sync.Mutex
	services map[string]any
}

func (r *sqlTenancyStubRegistry) Provide(name string, svc any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("already provided: %s", name)
	}
	r.services[name] = svc
	return nil
}
func (r *sqlTenancyStubRegistry) Lookup(name string) (any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.services[name]
	return v, ok
}
func (r *sqlTenancyStubRegistry) MustLookup(name string) any {
	v, ok := r.Lookup(name)
	if !ok {
		panic("missing service: " + name)
	}
	return v
}

type sqlTenancyStubEventBus struct{}

func (sqlTenancyStubEventBus) Publish(context.Context, api.Event) {}
func (sqlTenancyStubEventBus) Subscribe(string, api.Handler) api.Subscription {
	return sqlTenancyStubSub{}
}

type sqlTenancyStubSub struct{}

func (sqlTenancyStubSub) Unsubscribe() {}

type sqlTenancyStubConfig struct{}

func (sqlTenancyStubConfig) Scoped(string) api.PluginConfig { return sqlTenancyStubPluginConfig{} }

type sqlTenancyStubPluginConfig struct{}

func (sqlTenancyStubPluginConfig) String(_, def string) string                        { return def }
func (sqlTenancyStubPluginConfig) Int(_ string, def int) int                          { return def }
func (sqlTenancyStubPluginConfig) Bool(_ string, def bool) bool                       { return def }
func (sqlTenancyStubPluginConfig) Duration(_ string, def time.Duration) time.Duration { return def }
func (sqlTenancyStubPluginConfig) Raw() map[string]any                                { return nil }

type sqlTenancyStubLogger struct{}

func (sqlTenancyStubLogger) Debug(string, ...any) {}
func (sqlTenancyStubLogger) Info(string, ...any)  {}
func (sqlTenancyStubLogger) Warn(string, ...any)  {}
func (sqlTenancyStubLogger) Error(string, ...any) {}

type sqlTenancyStubKernel struct{ reg *sqlTenancyStubRegistry }

func (k sqlTenancyStubKernel) Registry() api.Registry     { return k.reg }
func (k sqlTenancyStubKernel) Events() api.EventBus       { return sqlTenancyStubEventBus{} }
func (k sqlTenancyStubKernel) Config() api.ConfigProvider { return sqlTenancyStubConfig{} }
func (k sqlTenancyStubKernel) Logger() api.Logger         { return sqlTenancyStubLogger{} }

var _ api.Kernel = sqlTenancyStubKernel{}

// plain in-memory api.StorageBackend, no scoping of its own — kv.Plugin
// is what applies tenant scoping on top of this, which is exactly the
// thing this test is verifying actually happens.
type sqlTenancyBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newSQLTenancyBackend() *sqlTenancyBackend {
	return &sqlTenancyBackend{data: map[string][]byte{}}
}
func (m *sqlTenancyBackend) Get(_ context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *sqlTenancyBackend) Put(_ context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *sqlTenancyBackend) Delete(_ context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}
func (m *sqlTenancyBackend) Batch(_ context.Context, ops []api.BatchOp) error {
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
func (m *sqlTenancyBackend) Scan(_ context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &sqlTenancyIter{backend: m, keys: keys, idx: -1}, nil
}
func (m *sqlTenancyBackend) Snapshot(context.Context) (api.Snapshot, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *sqlTenancyBackend) Close() error { return nil }

var _ api.StorageBackend = (*sqlTenancyBackend)(nil)

type sqlTenancyIter struct {
	backend *sqlTenancyBackend
	keys    []string
	idx     int
}

func (it *sqlTenancyIter) Next() bool  { it.idx++; return it.idx < len(it.keys) }
func (it *sqlTenancyIter) Key() []byte { return []byte(it.keys[it.idx]) }
func (it *sqlTenancyIter) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}
func (it *sqlTenancyIter) Err() error   { return nil }
func (it *sqlTenancyIter) Close() error { return nil }

var _ api.Iterator = (*sqlTenancyIter)(nil)

// bootRealTenantAwareKV boots the REAL plugins/kv.Plugin (not a fake)
// atop a plain in-memory backend, so its own genuine storageFor(ctx)
// tenant-scoping is what this test exercises.
func bootRealTenantAwareKV(t *testing.T) api.KVService {
	t.Helper()
	reg := &sqlTenancyStubRegistry{services: map[string]any{}}
	if err := reg.Provide("storage", newSQLTenancyBackend()); err != nil {
		t.Fatalf("Provide storage: %v", err)
	}
	k := sqlTenancyStubKernel{reg: reg}

	p := kv.New("storage")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("kv.Init: %v", err)
	}
	svc, ok := reg.Lookup("kv")
	if !ok {
		t.Fatalf("kv plugin did not register itself under service name %q", "kv")
	}
	return svc.(api.KVService)
}

// TestTenantIsolation_SQL proves that SQL gets tenant isolation "for
// free" once given a genuinely tenant-aware api.KVService, WITHOUT any
// tenant-scoping logic of its own in plugins/sql — because Engine.Exec/
// Query (and tx.Exec/Query, including the just-fixed Rollback path)
// correctly propagate the caller's ctx all the way down to every e.kv
// call, and kv.Plugin itself applies tenant scoping transparently at
// that layer. This is a real, executed proof, not a design assumption.
func TestTenantIsolation_SQL(t *testing.T) {
	kvSvc := bootRealTenantAwareKV(t)
	eng := NewEngine(kvSvc)

	ctxA := api.WithTenant(context.Background(), "tenant-a")
	ctxB := api.WithTenant(context.Background(), "tenant-b")

	// Same table name, same schema, under two different tenants.
	if _, err := eng.Exec(ctxA, `CREATE TABLE accounts (id INT PRIMARY KEY, name VARCHAR(255))`); err != nil {
		t.Fatalf("tenant-a CREATE TABLE: %v", err)
	}
	if _, err := eng.Exec(ctxB, `CREATE TABLE accounts (id INT PRIMARY KEY, name VARCHAR(255))`); err != nil {
		t.Fatalf("tenant-b CREATE TABLE: %v", err)
	}

	if _, err := eng.Exec(ctxA, `INSERT INTO accounts (id, name) VALUES (1, 'alice-a')`); err != nil {
		t.Fatalf("tenant-a INSERT: %v", err)
	}
	if _, err := eng.Exec(ctxB, `INSERT INTO accounts (id, name) VALUES (1, 'bob-b')`); err != nil {
		t.Fatalf("tenant-b INSERT: %v", err)
	}

	// Direct PK lookup: tenant A must see ONLY its own row.
	rowsA, err := eng.Query(ctxA, `SELECT name FROM accounts WHERE id = 1`)
	if err != nil {
		t.Fatalf("tenant-a SELECT by PK: %v", err)
	}
	if len(rowsA) != 1 || rowsA[0]["name"] != "alice-a" {
		t.Fatalf("tenant-a PK lookup leaked or missing data: %+v", rowsA)
	}
	rowsB, err := eng.Query(ctxB, `SELECT name FROM accounts WHERE id = 1`)
	if err != nil {
		t.Fatalf("tenant-b SELECT by PK: %v", err)
	}
	if len(rowsB) != 1 || rowsB[0]["name"] != "bob-b" {
		t.Fatalf("tenant-b PK lookup leaked or missing data: %+v", rowsB)
	}

	// The trickiest case: an INDEXED equality WHERE lookup (not the PK
	// fast path) must not leak across tenants either — insert a second,
	// differently-named row under each tenant and query by the `name`
	// column, which the engine auto-indexes.
	if _, err := eng.Exec(ctxA, `INSERT INTO accounts (id, name) VALUES (2, 'shared-label')`); err != nil {
		t.Fatalf("tenant-a INSERT 2: %v", err)
	}
	if _, err := eng.Exec(ctxB, `INSERT INTO accounts (id, name) VALUES (2, 'shared-label')`); err != nil {
		t.Fatalf("tenant-b INSERT 2: %v", err)
	}
	idxA, err := eng.Query(ctxA, `SELECT id FROM accounts WHERE name = 'shared-label'`)
	if err != nil {
		t.Fatalf("tenant-a indexed SELECT: %v", err)
	}
	if len(idxA) != 1 {
		t.Fatalf("tenant-a indexed lookup should see exactly its own 1 row, got %d: %+v", len(idxA), idxA)
	}
	idxB, err := eng.Query(ctxB, `SELECT id FROM accounts WHERE name = 'shared-label'`)
	if err != nil {
		t.Fatalf("tenant-b indexed SELECT: %v", err)
	}
	if len(idxB) != 1 {
		t.Fatalf("tenant-b indexed lookup should see exactly its own 1 row, got %d: %+v", len(idxB), idxB)
	}

	// No-tenant context must see NEITHER tenant's table data (proves this
	// isn't just "different values," but a genuinely separate keyspace —
	// a fresh CREATE TABLE under no-tenant context must succeed, which it
	// would NOT if it collided with either tenant's existing schema key).
	if _, err := eng.Exec(context.Background(), `CREATE TABLE accounts (id INT PRIMARY KEY, name VARCHAR(255))`); err != nil {
		t.Fatalf("no-tenant CREATE TABLE should succeed on a fresh keyspace, got: %v", err)
	}
	rowsNoTenant, err := eng.Query(context.Background(), `SELECT name FROM accounts WHERE id = 1`)
	if err != nil {
		t.Fatalf("no-tenant SELECT: %v", err)
	}
	if len(rowsNoTenant) != 0 {
		t.Fatalf("no-tenant context should not see either tenant's row 1, got: %+v", rowsNoTenant)
	}

	// Transaction path (including the Rollback ctx-propagation fix):
	// stage a write under tenant A inside a Tx, roll it back, confirm the
	// undo replay correctly targeted tenant A's own keyspace (not the
	// global one) by checking tenant A is back to exactly its original 2
	// rows and no stray row leaked into the global/no-tenant keyspace.
	tx, err := eng.Begin(ctxA)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(ctxA, `INSERT INTO accounts (id, name) VALUES (3, 'temp-a')`); err != nil {
		t.Fatalf("tx Exec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	afterRollbackA, err := eng.Query(ctxA, `SELECT id FROM accounts`)
	if err != nil {
		t.Fatalf("tenant-a post-rollback SELECT: %v", err)
	}
	if len(afterRollbackA) != 2 {
		t.Fatalf("tenant-a should have exactly 2 rows after rollback (the rolled-back INSERT undone), got %d: %+v", len(afterRollbackA), afterRollbackA)
	}
	afterRollbackGlobal, err := eng.Query(context.Background(), `SELECT id FROM accounts WHERE id = 3`)
	if err != nil {
		t.Fatalf("global post-rollback SELECT: %v", err)
	}
	if len(afterRollbackGlobal) != 0 {
		t.Fatalf("rollback must not have leaked row id=3 into the global/no-tenant keyspace, got: %+v", afterRollbackGlobal)
	}
}

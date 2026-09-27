package tenancy

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// memBackend is a minimal in-test api.StorageBackend stub, self-contained
// (no dependency on plugins/storage-mem), matching the convention used
// throughout this codebase's other plugin test suites.
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (b *memBackend) Get(_ context.Context, key []byte) ([]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[string(key)]
	return v, ok, nil
}
func (b *memBackend) Put(_ context.Context, e api.Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[string(e.Key)] = e.Value
	return nil
}
func (b *memBackend) Delete(_ context.Context, key []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, string(key))
	return nil
}
func (b *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	for _, op := range ops {
		if op.Delete {
			if err := b.Delete(ctx, op.Entry.Key); err != nil {
				return err
			}
			continue
		}
		if err := b.Put(ctx, op.Entry); err != nil {
			return err
		}
	}
	return nil
}
func (b *memBackend) Scan(_ context.Context, prefix []byte) (api.Iterator, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []string
	for k := range b.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == string(prefix)) {
			keys = append(keys, k)
		}
	}
	return &memIterator{backend: b, keys: keys, idx: -1}, nil
}
func (b *memBackend) Snapshot(context.Context) (api.Snapshot, error) {
	return nil, errors.New("not implemented")
}
func (b *memBackend) Close() error { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool  { it.idx++; return it.idx < len(it.keys) }
func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }
func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}
func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

func newTestPlugin() *Plugin {
	return &Plugin{storage: newMemBackend()}
}

func TestCreateGetSetDeleteTenant(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.CreateTenant(ctx, "acme", api.TenantQuota{MaxKeys: 10, MaxBytes: 1000}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	q, ok, err := p.GetQuota(ctx, "acme")
	if err != nil || !ok || q.MaxKeys != 10 || q.MaxBytes != 1000 {
		t.Fatalf("GetQuota = %+v, %v, %v", q, ok, err)
	}

	if err := p.SetQuota(ctx, "acme", api.TenantQuota{MaxKeys: 20}); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	q, ok, err = p.GetQuota(ctx, "acme")
	if err != nil || !ok || q.MaxKeys != 20 {
		t.Fatalf("GetQuota after SetQuota = %+v, %v, %v", q, ok, err)
	}

	if err := p.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	_, ok, err = p.GetQuota(ctx, "acme")
	if err != nil || ok {
		t.Fatalf("expected tenant gone after DeleteTenant, ok=%v err=%v", ok, err)
	}
}

func TestCreateTenant_RejectsInvalidID(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	if err := p.CreateTenant(ctx, "has/slash", api.TenantQuota{}); err == nil {
		t.Fatalf("expected error for tenant ID containing '/'")
	}
	if err := p.CreateTenant(ctx, "", api.TenantQuota{}); err == nil {
		t.Fatalf("expected error for empty tenant ID")
	}
}

func TestUsage_ReflectsDataUnderTenantPrefix(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	// Simulate kv/object having written data under this tenant's prefix
	// (the exact scheme their own tenantScope wrappers use).
	_ = p.storage.Put(ctx, api.Entry{Key: []byte("tenant/acme/foo"), Value: []byte("12345")})
	_ = p.storage.Put(ctx, api.Entry{Key: []byte("tenant/acme/bar"), Value: []byte("67")})
	_ = p.storage.Put(ctx, api.Entry{Key: []byte("tenant/other/baz"), Value: []byte("should-not-count")})

	keys, bytesTotal, err := p.Usage(ctx, "acme")
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if keys != 2 {
		t.Fatalf("expected 2 keys, got %d", keys)
	}
	if bytesTotal != 7 { // len("12345") + len("67")
		t.Fatalf("expected 7 bytes, got %d", bytesTotal)
	}
}

func TestDeleteTenant_RemovesOnlyThatTenantsData(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	_ = p.CreateTenant(ctx, "acme", api.TenantQuota{})
	_ = p.CreateTenant(ctx, "other", api.TenantQuota{})
	_ = p.storage.Put(ctx, api.Entry{Key: []byte("tenant/acme/foo"), Value: []byte("v1")})
	_ = p.storage.Put(ctx, api.Entry{Key: []byte("tenant/other/foo"), Value: []byte("v2")})

	if err := p.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}

	if _, ok, _ := p.storage.Get(ctx, []byte("tenant/acme/foo")); ok {
		t.Fatalf("expected acme's data to be gone")
	}
	if v, ok, _ := p.storage.Get(ctx, []byte("tenant/other/foo")); !ok || string(v) != "v2" {
		t.Fatalf("other tenant's data should be untouched, got ok=%v v=%q", ok, v)
	}
	if _, ok, _ := p.GetQuota(ctx, "other"); !ok {
		t.Fatalf("other tenant's metadata should still exist")
	}
}

func TestListTenants(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	_ = p.CreateTenant(ctx, "a", api.TenantQuota{})
	_ = p.CreateTenant(ctx, "b", api.TenantQuota{})

	list, err := p.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tenants, got %v", list)
	}
}

package kv

import (
	"context"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

func TestTenants_IdenticalKeysDoNotCollide(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ctxA := api.WithTenant(ctx, "tenant-a")
	ctxB := api.WithTenant(ctx, "tenant-b")

	if err := p.Put(ctxA, "shared-key", []byte("value-A")); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if err := p.Put(ctxB, "shared-key", []byte("value-B")); err != nil {
		t.Fatalf("Put B: %v", err)
	}

	vA, ok, err := p.Get(ctxA, "shared-key")
	if err != nil || !ok || string(vA) != "value-A" {
		t.Fatalf("Get A = %q, %v, %v", vA, ok, err)
	}
	vB, ok, err := p.Get(ctxB, "shared-key")
	if err != nil || !ok || string(vB) != "value-B" {
		t.Fatalf("Get B = %q, %v, %v", vB, ok, err)
	}
}

func TestTenants_ScanNeverLeaksAcrossTenantsEvenWithCraftedKeys(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ctxA := api.WithTenant(ctx, "a")
	ctxB := api.WithTenant(ctx, "b")

	_ = p.Put(ctxA, "normal-key", []byte("A-data"))
	// A key crafted to LOOK like it could escape tenant "b"'s prefix if
	// isolation were naive string concatenation without a safe delimiter
	// guarantee. Since tenant IDs can never contain "/", and this is a
	// byte-string keyspace (not a filesystem), this is just ordinary key
	// content to tenant "b" — it must never become visible to tenant "a".
	_ = p.Put(ctxB, "../a/normal-key", []byte("B-should-not-leak"))
	_ = p.Put(ctxB, "tenant/a/normal-key", []byte("B-should-not-leak-2"))

	keysA, err := p.Keys(ctxA, "*")
	if err != nil {
		t.Fatalf("Keys A: %v", err)
	}
	if len(keysA) != 1 || keysA[0] != "normal-key" {
		t.Fatalf("tenant A's Keys leaked or missed data: %v", keysA)
	}

	items, _, err := p.Scan(ctxA, "", 100, "")
	if err != nil {
		t.Fatalf("Scan A: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("tenant A's Scan leaked tenant B's data: %v", items)
	}
	if v, ok := items["normal-key"]; !ok || string(v) != "A-data" {
		t.Fatalf("tenant A's own data corrupted: %v", items)
	}
}

func TestTenants_NoTenantInContextIsUnchangedGlobalBehavior(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.Put(ctx, "global-key", []byte("global-value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, ok, err := p.Get(ctx, "global-key")
	if err != nil || !ok || string(v) != "global-value" {
		t.Fatalf("Get = %q, %v, %v", v, ok, err)
	}

	// Confirm the raw storage key has NO tenant prefix at all when no
	// tenant is in context — i.e. this is genuinely the same global
	// keyspace as before tenancy existed, not silently tenant-scoped to
	// some default.
	raw, ok, err := p.storage.Get(ctx, []byte("global-key"))
	if err != nil || !ok || string(raw) != "global-value" {
		t.Fatalf("expected raw backend key %q to exist untouched, got %q, %v, %v", "global-key", raw, ok, err)
	}
}

// stubTenancy is a minimal in-test api.TenantService for quota tests,
// independent of the real plugins/tenancy package (avoids an import
// cycle risk and keeps this test self-contained).
type stubTenancy struct {
	quotas map[string]api.TenantQuota
	usageK map[string]int64
	usageB map[string]int64
}

func newStubTenancy() *stubTenancy {
	return &stubTenancy{quotas: map[string]api.TenantQuota{}, usageK: map[string]int64{}, usageB: map[string]int64{}}
}

func (s *stubTenancy) CreateTenant(ctx context.Context, id string, q api.TenantQuota) error {
	s.quotas[id] = q
	return nil
}
func (s *stubTenancy) DeleteTenant(ctx context.Context, id string) error {
	delete(s.quotas, id)
	return nil
}
func (s *stubTenancy) GetQuota(ctx context.Context, id string) (api.TenantQuota, bool, error) {
	q, ok := s.quotas[id]
	return q, ok, nil
}
func (s *stubTenancy) SetQuota(ctx context.Context, id string, q api.TenantQuota) error {
	s.quotas[id] = q
	return nil
}
func (s *stubTenancy) Usage(ctx context.Context, id string) (int64, int64, error) {
	return s.usageK[id], s.usageB[id], nil
}
func (s *stubTenancy) ListTenants(ctx context.Context) ([]string, error) {
	var out []string
	for id := range s.quotas {
		out = append(out, id)
	}
	return out, nil
}

var _ api.TenantService = (*stubTenancy)(nil)

func TestTenants_QuotaEnforcement(t *testing.T) {
	ctx := context.Background()
	tenancy := newStubTenancy()
	_ = tenancy.CreateTenant(ctx, "limited", api.TenantQuota{MaxKeys: 2})
	// Pre-seed usage as if one key already exists, so the SECOND Put in
	// this test is the one that would exceed MaxKeys=2.
	tenancy.usageK["limited"] = 1

	p := newTestPlugin()
	p.tenancy = tenancy

	tctx := api.WithTenant(ctx, "limited")

	if err := p.Put(tctx, "key1", []byte("v")); err != nil {
		t.Fatalf("first put under quota should succeed: %v", err)
	}
	// Simulate the real Usage reflecting the just-added key, as the real
	// tenancy plugin's Scan-based Usage would after a real Put.
	tenancy.usageK["limited"] = 2

	if err := p.Put(tctx, "key2", []byte("v")); err == nil {
		t.Fatalf("expected quota-exceeded error, got nil")
	}

	// Free up quota (simulating a Delete reducing usage) and confirm a
	// subsequent Put succeeds again.
	tenancy.usageK["limited"] = 1
	if err := p.Put(tctx, "key2", []byte("v")); err != nil {
		t.Fatalf("put after quota freed up should succeed: %v", err)
	}
}

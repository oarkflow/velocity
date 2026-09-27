package iam

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// --- minimal in-memory StorageBackend stub, kept local to this test so it
// doesn't depend on the storage-mem plugin package (built separately). ---

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
	return nil, nil
}

func (m *memBackend) Close() error { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool {
	it.idx++
	return it.idx < len(it.keys)
}

func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }

func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}

func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

// --- tests ---

func TestPolicyCRUDRoundTrip(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	ctx := context.Background()

	pol := api.IAMPolicy{Statements: []api.IAMStatement{
		{Effect: "Allow", Actions: []string{"kv:*"}, Resources: []string{"*"}},
	}}
	if err := p.PutPolicy(ctx, "reader", pol); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}

	got, err := p.GetPolicy(ctx, "reader")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name != "reader" || len(got.Statements) != 1 {
		t.Fatalf("unexpected policy: %+v", got)
	}

	names, err := p.ListPolicies(ctx)
	if err != nil || len(names) != 1 || names[0] != "reader" {
		t.Fatalf("ListPolicies = %v, %v", names, err)
	}

	if err := p.DeletePolicy(ctx, "reader"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if _, err := p.GetPolicy(ctx, "reader"); err == nil {
		t.Fatal("expected error getting deleted policy")
	}
}

// TestPolicyPersistsAcrossFreshInstance proves policies are genuinely
// persisted via the StorageBackend, not just held in the struct — a
// second Plugin instance opening the SAME backend sees the same data.
func TestPolicyPersistsAcrossFreshInstance(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()

	p1 := &Plugin{storage: backend}
	if err := p1.PutPolicy(ctx, "reader", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"kv:Get"}, Resources: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if err := p1.AttachPolicy(ctx, "alice", "reader"); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	// Fresh instance, same backend, nothing carried over in Go memory.
	p2 := &Plugin{storage: backend}
	pol, err := p2.GetPolicy(ctx, "reader")
	if err != nil {
		t.Fatalf("GetPolicy on fresh instance: %v", err)
	}
	if len(pol.Statements) != 1 {
		t.Fatalf("policy not persisted correctly: %+v", pol)
	}
	allowed, _, err := p2.Evaluate(ctx, "alice", "kv:Get", "anything")
	if err != nil || !allowed {
		t.Fatalf("Evaluate on fresh instance = %v, %v, want allowed", allowed, err)
	}
}

func TestWildcardActionAndResourceMatching(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	ctx := context.Background()

	if err := p.PutPolicy(ctx, "kv-only", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"kv:*"}, Resources: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if err := p.AttachPolicy(ctx, "bob", "kv-only"); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	cases := []struct {
		action string
		want   bool
	}{
		{"kv:Put", true},
		{"kv:Get", true},
		{"object:Put", false},
		{"object:Get", false},
	}
	for _, c := range cases {
		allowed, reason, err := p.Evaluate(ctx, "bob", c.action, "res")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", c.action, err)
		}
		if allowed != c.want {
			t.Fatalf("Evaluate(%q) = %v (%s), want %v", c.action, allowed, reason, c.want)
		}
	}
}

// TestExplicitDenyWinsOverAllow is the core IAM-correctness proof: a
// principal with one policy granting Allow and another granting Deny for
// the SAME action/resource must be denied — Deny always wins, regardless
// of attachment order.
func TestExplicitDenyWinsOverAllow(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	ctx := context.Background()

	if err := p.PutPolicy(ctx, "allow-all", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy allow-all: %v", err)
	}
	if err := p.PutPolicy(ctx, "deny-delete", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Deny", Actions: []string{"object:Delete"}, Resources: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy deny-delete: %v", err)
	}
	if err := p.AttachPolicy(ctx, "carol", "allow-all"); err != nil {
		t.Fatalf("attach allow-all: %v", err)
	}
	if err := p.AttachPolicy(ctx, "carol", "deny-delete"); err != nil {
		t.Fatalf("attach deny-delete: %v", err)
	}

	// Allowed by allow-all, not touched by deny-delete's narrower scope.
	allowed, _, err := p.Evaluate(ctx, "carol", "object:Get", "res")
	if err != nil || !allowed {
		t.Fatalf("object:Get should be allowed: %v, %v", allowed, err)
	}

	// Would be allowed by allow-all's "*", but deny-delete must win.
	allowed, reason, err := p.Evaluate(ctx, "carol", "object:Delete", "res")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatalf("object:Delete should be denied (explicit Deny must win over Allow), reason=%q", reason)
	}
	if !strings.Contains(reason, "Deny") {
		t.Fatalf("reason should cite the Deny: %q", reason)
	}
}

// TestImplicitDenyByDefault is the second core correctness proof: a
// principal with a policy that doesn't mention the requested action/
// resource at all must be denied, not allowed — no policy match means
// implicit deny, never implicit allow.
func TestImplicitDenyByDefault(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	ctx := context.Background()

	if err := p.PutPolicy(ctx, "kv-reader", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"kv:Get"}, Resources: []string{"kv/*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if err := p.AttachPolicy(ctx, "dave", "kv-reader"); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	// Not covered by kv-reader's statement at all.
	allowed, reason, err := p.Evaluate(ctx, "dave", "object:Delete", "bucket/x")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatalf("unmatched action/resource must be implicit deny, got allowed (reason=%q)", reason)
	}
	if !strings.Contains(reason, "implicit") {
		t.Fatalf("reason should say implicit deny: %q", reason)
	}

	// A principal with NO attached policies at all must also be denied.
	allowed, _, err = p.Evaluate(ctx, "nobody", "kv:Get", "kv/x")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Fatal("a principal with zero attached policies must be denied, not allowed")
	}
}

func TestDetachPolicyRemovesAccess(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	ctx := context.Background()

	if err := p.PutPolicy(ctx, "reader", api.IAMPolicy{
		Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"kv:Get"}, Resources: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if err := p.AttachPolicy(ctx, "erin", "reader"); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
	if allowed, _, _ := p.Evaluate(ctx, "erin", "kv:Get", "x"); !allowed {
		t.Fatal("expected allowed before detach")
	}

	if err := p.DetachPolicy(ctx, "erin", "reader"); err != nil {
		t.Fatalf("DetachPolicy: %v", err)
	}
	if allowed, _, _ := p.Evaluate(ctx, "erin", "kv:Get", "x"); allowed {
		t.Fatal("expected denied after detach")
	}
}

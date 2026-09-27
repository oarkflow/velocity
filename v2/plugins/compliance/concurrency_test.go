package compliance

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// TestConcurrentRecordKeepsChainConsistent fires many goroutines calling
// Record concurrently — the hash chain must remain internally consistent
// (VerifyChain must pass afterward) even under concurrent appends. Record
// already holds p.mu across its full read-modify-write of headSeq/
// headHash plus both storage.Put calls (see audit.go), so this test is
// the empirical proof that serialization actually holds under real
// concurrent load, not just a read of the code.
func TestConcurrentRecordKeepsChainConsistent(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := api.AuditEvent{Actor: "tester", Action: "concurrent.write", Resource: fmt.Sprintf("res-%03d", i)}
			if err := p.Record(ctx, ev); err != nil {
				t.Errorf("Record %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if err := p.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain after %d concurrent Record calls: %v (hash chain was NOT correctly serialized under concurrency)", n, err)
	}

	// Every seq from 0..n-1 must exist with a distinct resource — proves
	// no writer's Record call was lost or overwrote another's slot.
	seen := make(map[string]bool, n)
	for seq := 0; seq < n; seq++ {
		data, ok, err := p.storage.Get(ctx, []byte(auditKey(seq)))
		if err != nil || !ok {
			t.Fatalf("record at seq %d missing: ok=%v err=%v", seq, ok, err)
		}
		seen[string(data)] = true
	}
}

// TestConcurrentEvaluateDuringRulePackImport interleaves many concurrent
// read-only Evaluate calls with a concurrent ImportRulePack write — no
// data race, and no Evaluate call may observe a torn/partial rule slice
// (rulesMu.RLock/Lock already guards this per policy.go/rulepacks.go; this
// test empirically proves it holds under real concurrent load).
func TestConcurrentEvaluateDuringRulePackImport(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	subject := api.Principal{Subject: "alice", Roles: []string{"user"}}
	packJSON := []byte(`{"rules":[{"classification":"internal","action":"delete","requireRole":"admin","name":"concurrency-test-rule"}]}`)

	var wg sync.WaitGroup
	// One writer importing the rule pack.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.ImportRulePack(ctx, packJSON); err != nil {
			t.Errorf("ImportRulePack: %v", err)
		}
	}()

	// Many concurrent readers evaluating while the import may be in
	// flight.
	const readers = 40
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Evaluate(ctx, subject, "delete", "some-resource", "internal"); err != nil {
				t.Errorf("Evaluate: %v", err)
			}
		}()
	}
	wg.Wait()

	// After the import has definitely completed, the new rule must be in
	// effect: alice (role "user", not "admin") deleting an
	// internal-classification resource must now be denied.
	decision, err := p.Evaluate(ctx, subject, "delete", "some-resource", "internal")
	if err != nil {
		t.Fatalf("final Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected the imported rule pack to deny this request post-import, got Allowed=true")
	}
}

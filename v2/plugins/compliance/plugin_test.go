package compliance

import (
	"context"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	mem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

// bootTestKernel builds a real kernel.Kernel, provides an in-memory
// StorageBackend under the fixed "storage" service name (as whichever
// concrete storage plugin would in a real boot), and returns it alongside
// the underlying backend for direct tampering in tests.
func bootTestKernel(t *testing.T) (*kernel.Kernel, api.StorageBackend) {
	t.Helper()
	k := kernel.New(kernel.Manifest{})
	backend := mem.NewEngine()
	if err := k.Registry().Provide("storage", backend); err != nil {
		t.Fatalf("providing storage: %v", err)
	}
	return k, backend
}

func TestAuditChain_RecordAndVerify(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for i := 0; i < 5; i++ {
		ev := api.AuditEvent{Actor: "tester", Action: "kv.put", Resource: "key-" + string(rune('a'+i))}
		if err := p.Record(ctx, ev); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	if err := p.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain on untampered chain: %v", err)
	}
}

func TestAuditChain_DetectsTampering(t *testing.T) {
	ctx := context.Background()
	k, backend := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := p.Record(ctx, api.AuditEvent{Actor: "tester", Action: "kv.put", Resource: "key"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	if err := p.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain before tampering: %v", err)
	}

	// Directly corrupt the persisted record at seq 1: change the Event's
	// Resource field in place without recomputing the hash, exactly
	// simulating an out-of-band tamper attempt.
	data, ok, err := backend.Get(ctx, []byte(auditKey(1)))
	if err != nil || !ok {
		t.Fatalf("reading record 1 for tampering: ok=%v err=%v", ok, err)
	}
	tampered := strings.Replace(string(data), `"Resource":"key"`, `"Resource":"tampered"`, 1)
	if tampered == string(data) {
		t.Fatalf("tamper replacement did not match record 1 contents: %s", data)
	}
	if err := backend.Put(ctx, api.Entry{Key: []byte(auditKey(1)), Value: []byte(tampered)}); err != nil {
		t.Fatalf("writing tampered record: %v", err)
	}

	if err := p.VerifyChain(ctx); err == nil {
		t.Fatal("VerifyChain succeeded on a tampered chain, expected an error")
	} else {
		t.Logf("VerifyChain correctly detected tampering: %v", err)
	}
}

// TestComplianceMethods_ErrorWhenUnwired is the regression guard for the
// v1 bug this plugin fixes: v1's GDPRController silently returned nil
// (success) from RecordConsent/ApplyRetention when its underlying manager
// was nil. Here, a Plugin that was never Init'd (storage is nil) must
// return a real error, never nil, from every ComplianceService method
// that touches storage.
func TestComplianceMethods_ErrorWhenUnwired(t *testing.T) {
	ctx := context.Background()
	p := NewPlugin("storage-mem") // deliberately never call Init

	if err := p.ApplyRetention(ctx, "some/resource"); err == nil {
		t.Error("ApplyRetention on unwired plugin returned nil, want an error (this is the v1 bug)")
	}
	if err := p.RecordConsent(ctx, "subject-1", "marketing", true); err == nil {
		t.Error("RecordConsent on unwired plugin returned nil, want an error (this is the v1 bug)")
	}
	if err := p.Anonymize(ctx, "some/resource"); err == nil {
		t.Error("Anonymize on unwired plugin returned nil, want an error")
	}
	if err := p.Record(ctx, api.AuditEvent{Actor: "x", Action: "y", Resource: "z"}); err == nil {
		t.Error("Record on unwired plugin returned nil, want an error")
	}
	if err := p.VerifyChain(ctx); err == nil {
		t.Error("VerifyChain on unwired plugin returned nil, want an error")
	}
	if _, err := p.HasConsent(ctx, "subject-1", "marketing"); err == nil {
		t.Error("HasConsent on unwired plugin returned nil error, want an error")
	}
}

func TestEvaluate_AllowAndDeny(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Allow: public data, no special role needed.
	decision, err := p.Evaluate(ctx, api.Principal{Subject: "u1"}, "read", "doc-1", "public")
	if err != nil {
		t.Fatalf("Evaluate (allow case): %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected public/read to be allowed, got denied: %s", decision.Reason)
	}

	// Deny: restricted data, subject has no admin role.
	decision, err = p.Evaluate(ctx, api.Principal{Subject: "u1", Roles: []string{"user"}}, "read", "doc-2", "restricted")
	if err != nil {
		t.Fatalf("Evaluate (deny case): %v", err)
	}
	if decision.Allowed {
		t.Error("expected restricted/read without admin role to be denied, got allowed")
	}

	// Allow: restricted data, subject has admin role.
	decision, err = p.Evaluate(ctx, api.Principal{Subject: "admin1", Roles: []string{"admin"}}, "read", "doc-2", "restricted")
	if err != nil {
		t.Fatalf("Evaluate (admin allow case): %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected restricted/read with admin role to be allowed, got denied: %s", decision.Reason)
	}
}

func TestApplyRetention_RespectsLegalHold(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := p.SetLegalHold(ctx, "res-1", true); err != nil {
		t.Fatalf("SetLegalHold: %v", err)
	}
	if err := p.ApplyRetention(ctx, "res-1"); err != nil {
		t.Fatalf("ApplyRetention under legal hold should not error, got: %v", err)
	}
}

func TestAnonymize_RewritesValue(t *testing.T) {
	ctx := context.Background()
	k, backend := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := backend.Put(ctx, api.Entry{Key: []byte("pii/user-1"), Value: []byte("john.doe@example.com")}); err != nil {
		t.Fatalf("seeding value: %v", err)
	}
	if err := p.Anonymize(ctx, "pii/user-1"); err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	data, ok, err := backend.Get(ctx, []byte("pii/user-1"))
	if err != nil || !ok {
		t.Fatalf("reading anonymized value: ok=%v err=%v", ok, err)
	}
	if string(data) == "john.doe@example.com" {
		t.Error("Anonymize did not rewrite the stored value")
	}
}

package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestClassification_SetAndGet(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := p.SetClassification(ctx, "obj/secret-doc", "restricted"); err != nil {
		t.Fatalf("SetClassification: %v", err)
	}
	rec, err := p.GetClassification(ctx, "obj/secret-doc")
	if err != nil {
		t.Fatalf("GetClassification: %v", err)
	}
	if rec.Level != "restricted" || rec.Resource != "obj/secret-doc" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	if _, err := p.GetClassification(ctx, "obj/never-set"); err == nil {
		t.Fatal("expected error for resource with no classification set")
	}
}

func TestResidency_ChecksRegion(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := p.SetResidencyRule(ctx, api.ResidencyRule{ResourcePrefix: "obj/eu/", Region: "eu-west-1"}); err != nil {
		t.Fatalf("SetResidencyRule: %v", err)
	}

	ok, reason, err := p.CheckResidency(ctx, "obj/eu/customer-1", "eu-west-1")
	if err != nil || !ok {
		t.Fatalf("expected allowed, got ok=%v reason=%q err=%v", ok, reason, err)
	}

	ok, reason, err = p.CheckResidency(ctx, "obj/eu/customer-1", "us-east-1")
	if err != nil {
		t.Fatalf("CheckResidency: %v", err)
	}
	if ok || reason == "" {
		t.Fatalf("expected denial with a reason, got ok=%v reason=%q", ok, reason)
	}

	// No matching rule at all -> unconstrained.
	ok, _, err = p.CheckResidency(ctx, "obj/unrelated/thing", "anywhere")
	if err != nil || !ok {
		t.Fatalf("expected allowed for unmatched prefix, got ok=%v err=%v", ok, err)
	}
}

func TestLineage_RecordAndQueryInOrder(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	actions := []string{"create", "update", "delete"}
	for _, a := range actions {
		if err := p.RecordLineage(ctx, api.LineageEvent{Resource: "obj/x", Action: a}); err != nil {
			t.Fatalf("RecordLineage(%s): %v", a, err)
		}
		time.Sleep(time.Millisecond) // ensure distinct nanosecond timestamps
	}

	events, err := p.GetLineage(ctx, "obj/x")
	if err != nil {
		t.Fatalf("GetLineage: %v", err)
	}
	if len(events) != len(actions) {
		t.Fatalf("expected %d events, got %d", len(actions), len(events))
	}
	for i, a := range actions {
		if events[i].Action != a {
			t.Fatalf("event %d: expected action %q, got %q (order not preserved)", i, a, events[i].Action)
		}
	}
}

func TestMaskWithStrategy_ProducesDifferentOutputPerStrategy(t *testing.T) {
	ctx := context.Background()
	k, backend := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	const resource = "secret/api-key"
	const value = "sk-1234567890"

	reset := func() {
		if err := backend.Put(ctx, api.Entry{Key: []byte(resource), Value: []byte(value)}); err != nil {
			t.Fatalf("reset value: %v", err)
		}
	}

	reset()
	if err := p.MaskWithStrategy(ctx, resource, api.MaskFull); err != nil {
		t.Fatalf("MaskWithStrategy full: %v", err)
	}
	full, _, _ := backend.Get(ctx, []byte(resource))
	if string(full) != "*************" {
		t.Fatalf("full mask: got %q", full)
	}

	reset()
	if err := p.MaskWithStrategy(ctx, resource, api.MaskPartial); err != nil {
		t.Fatalf("MaskWithStrategy partial: %v", err)
	}
	partial, _, _ := backend.Get(ctx, []byte(resource))
	if string(partial) != "*********7890" {
		t.Fatalf("partial mask: got %q", partial)
	}

	reset()
	if err := p.MaskWithStrategy(ctx, resource, api.MaskRedact); err != nil {
		t.Fatalf("MaskWithStrategy redact: %v", err)
	}
	redact, _, _ := backend.Get(ctx, []byte(resource))
	if string(redact) != "[REDACTED]" {
		t.Fatalf("redact mask: got %q", redact)
	}

	if full == nil || partial == nil || redact == nil {
		t.Fatal("expected all three masked reads to succeed")
	}
	if string(full) == string(partial) || string(partial) == string(redact) || string(full) == string(redact) {
		t.Fatal("expected three distinct outputs, strategies did not differentiate")
	}
}

func TestImportRulePack_ChangesEvaluateOutcome(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	subject := api.Principal{Subject: "alice", Roles: []string{"editor"}}

	// "internal" classification + "read" action is allowed by defaults.
	decision, err := p.Evaluate(ctx, subject, "read", "obj/y", "internal")
	if err != nil {
		t.Fatalf("Evaluate (pre-import): %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected default rules to allow this, got denied: %s", decision.Reason)
	}

	pack := []byte(`{"rules":[{"classification":"internal","action":"read","requireRole":"admin","reason":"custom pack: internal reads need admin","severity":"high"}]}`)
	if err := p.ImportRulePack(ctx, pack); err != nil {
		t.Fatalf("ImportRulePack: %v", err)
	}

	decision, err = p.Evaluate(ctx, subject, "read", "obj/y", "internal")
	if err != nil {
		t.Fatalf("Evaluate (post-import): %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected imported rule pack to deny this request")
	}
}

func TestViolations_DeniedEvaluateIsQueryable(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)
	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	subject := api.Principal{Subject: "bob", Roles: []string{"viewer"}}
	decision, err := p.Evaluate(ctx, subject, "delete", "obj/z", "restricted")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected default rules to deny a non-admin deleting restricted data")
	}

	violations, err := p.ListViolations(ctx, "obj/z")
	if err != nil {
		t.Fatalf("ListViolations: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 recorded violation, got %d", len(violations))
	}
	if violations[0].Severity != "critical" {
		t.Fatalf("expected severity carried over from the denying rule, got %q", violations[0].Severity)
	}

	all, err := p.ListViolations(ctx, "")
	if err != nil {
		t.Fatalf("ListViolations(\"\"): %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected ListViolations(\"\") to also see it, got %d", len(all))
	}
}

func TestViolations_WebhookRateLimited(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	var delivered int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Init already ran (rate limit defaulted to 60/min from config); override
	// directly for a fast, deterministic test instead of firing 60+ events.
	p.violationWebhookURL = srv.URL
	p.violationRateLimit = 3

	subject := api.Principal{Subject: "eve", Roles: []string{"viewer"}}
	const attempts = 10
	for i := 0; i < attempts; i++ {
		if _, err := p.Evaluate(ctx, subject, "delete", "obj/rl", "restricted"); err != nil {
			t.Fatalf("Evaluate %d: %v", i, err)
		}
	}

	// Webhook delivery happens synchronously inside Evaluate's call chain
	// in this implementation, so no extra wait is needed.
	got := atomic.LoadInt32(&delivered)
	if got != 3 {
		t.Fatalf("expected exactly 3 webhook deliveries (rate limit), got %d", got)
	}

	violations, err := p.ListViolations(ctx, "obj/rl")
	if err != nil {
		t.Fatalf("ListViolations: %v", err)
	}
	if len(violations) != attempts {
		t.Fatalf("expected all %d violations recorded regardless of webhook rate limit, got %d", attempts, len(violations))
	}
}

// ensure JSON round-trips cleanly for the exported types used above.
func TestViolationJSONShape(t *testing.T) {
	v := api.Violation{ID: "v-1", Rule: "r", Resource: "res", Severity: "high", At: time.Now()}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out api.Violation
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != v.ID || out.Severity != v.Severity {
		t.Fatalf("round trip mismatch: %+v vs %+v", v, out)
	}
}

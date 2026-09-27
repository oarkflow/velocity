// Command compliance_and_audit demonstrates Velocity v2's compliance
// plugin: the hash-chained audit trail, data classification/residency/
// lineage tracking, configurable masking strategies, rule-pack import,
// violation tracking, and break-glass emergency access with enforced
// segregation of duties.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/compliance"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-compliance-example-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
			{Name: "compliance", Enabled: true},
		},
	}

	k := kernel.New(manifest)
	ctx := context.Background()

	all := []api.Plugin{storagelsm.New(), compliance.NewPlugin("storage-lsm")}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	svc := k.Registry().MustLookup("compliance").(api.ComplianceService)

	fmt.Println("=== Audit trail: record events, then verify the hash chain ===")
	must(svc.Record(ctx, api.AuditEvent{Actor: "alice", Action: "login", Resource: "system"}))
	must(svc.Record(ctx, api.AuditEvent{Actor: "alice", Action: "read", Resource: "customers/42"}))
	must(svc.Record(ctx, api.AuditEvent{Actor: "alice", Action: "export", Resource: "customers/42"}))
	if err := svc.VerifyChain(ctx); err != nil {
		log.Fatalf("chain should be intact: %v", err)
	}
	fmt.Println("VerifyChain: PASS (3 events recorded, chain intact)")

	fmt.Println("\n=== Data classification ===")
	must(svc.SetClassification(ctx, "customers/42", "restricted"))
	rec, err := svc.GetClassification(ctx, "customers/42")
	must(err)
	fmt.Printf("customers/42 classification: %s (set at %s)\n", rec.Level, rec.SetAt.Format("15:04:05"))

	fmt.Println("\n=== Data residency ===")
	must(svc.SetResidencyRule(ctx, api.ResidencyRule{ResourcePrefix: "customers/", Region: "eu-west-1"}))
	ok, reason, err := svc.CheckResidency(ctx, "customers/42", "eu-west-1")
	must(err)
	fmt.Printf("check against eu-west-1 (matches rule): allowed=%v reason=%q\n", ok, reason)
	ok, reason, err = svc.CheckResidency(ctx, "customers/42", "us-east-1")
	must(err)
	fmt.Printf("check against us-east-1 (violates rule): allowed=%v reason=%q\n", ok, reason)

	fmt.Println("\n=== Data lineage ===")
	must(svc.RecordLineage(ctx, api.LineageEvent{Resource: "customers/42", Action: "create", Source: "signup-api"}))
	must(svc.RecordLineage(ctx, api.LineageEvent{Resource: "customers/42", Action: "update", Source: "support-portal"}))
	events, err := svc.GetLineage(ctx, "customers/42")
	must(err)
	for i, e := range events {
		fmt.Printf("  [%d] %s via %s at %s\n", i, e.Action, e.Source, e.At.Format("15:04:05"))
	}

	fmt.Println("\n=== Masking strategies ===")
	// MaskWithStrategy rewrites a value that's actually stored under
	// this key in the StorageBackend — write one directly (bypassing kv,
	// which this example doesn't boot) before masking it.
	storage := k.Registry().MustLookup("storage").(api.StorageBackend)
	must(storage.Put(ctx, api.Entry{Key: []byte("customers/42/email"), Value: []byte("alice@example.com")}))
	must(svc.SetClassification(ctx, "customers/42/email", "confidential"))
	for _, strategy := range []api.MaskStrategy{api.MaskFull, api.MaskPartial, api.MaskRedact} {
		must(storage.Put(ctx, api.Entry{Key: []byte("customers/42/email"), Value: []byte("alice@example.com")}))
		if err := svc.MaskWithStrategy(ctx, "customers/42/email", strategy); err != nil {
			fmt.Printf("  %-8s -> error: %v\n", strategy, err)
			continue
		}
		masked, _, err := storage.Get(ctx, []byte("customers/42/email"))
		must(err)
		fmt.Printf("  %-8s -> %q\n", strategy, string(masked))
	}

	fmt.Println("\n=== Rule-pack import changes policy outcomes ===")
	// "internal" classification isn't covered by any default rule, so an
	// analyst deleting internal-level data is allowed out of the box —
	// this is the case a rule pack can meaningfully change.
	subject := api.Principal{Subject: "bob", Roles: []string{"analyst"}}
	before, err := svc.Evaluate(ctx, subject, "delete", "logs/access-2026-09", "internal")
	must(err)
	fmt.Printf("before rule pack: analyst delete on 'internal' -> allowed=%v (%s)\n", before.Allowed, before.Reason)

	pack, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"name": "block-analyst-delete-internal", "classification": "internal", "action": "delete", "requireRole": "admin", "severity": "high"},
		},
	})
	must(svc.ImportRulePack(ctx, pack))

	after, err := svc.Evaluate(ctx, subject, "delete", "logs/access-2026-09", "internal")
	must(err)
	fmt.Printf("after rule pack:  analyst delete on 'internal' -> allowed=%v (%s)\n", after.Allowed, after.Reason)

	fmt.Println("\n=== Violations are queryable after the fact ===")
	violations, err := svc.ListViolations(ctx, "logs/access-2026-09")
	must(err)
	fmt.Printf("recorded violations for logs/access-2026-09: %d\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  rule=%s severity=%s at=%s\n", v.Rule, v.Severity, v.At.Format("15:04:05"))
	}

	fmt.Println("\n=== Break-glass emergency access (segregation of duties enforced) ===")
	bg, ok := any(svc).(api.BreakGlassService)
	if !ok {
		fmt.Println("compliance plugin does not implement api.BreakGlassService in this build")
		return
	}
	req := api.BreakGlassRequest{Requestor: "carol", Reason: "production incident #告", Resource: "customers/42"}

	grant, err := bg.BreakGlassGrant(ctx, req, api.Principal{Subject: "dave", Roles: []string{"admin"}})
	must(err)
	fmt.Printf("grant by distinct approver 'dave': SUCCEEDED, id=%s expires=%s\n", grant.ID, grant.ExpiresAt.Format("15:04:05"))
	must(bg.BreakGlassRevoke(ctx, grant.ID))
	fmt.Println("revoke: SUCCEEDED")

	_, err = bg.BreakGlassGrant(ctx, req, api.Principal{Subject: "carol", Roles: []string{"admin"}})
	if err != nil {
		fmt.Printf("grant with requestor==approver 'carol': REJECTED as expected (%v)\n", err)
	} else {
		fmt.Println("grant with requestor==approver: unexpectedly succeeded — segregation of duties not enforced!")
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

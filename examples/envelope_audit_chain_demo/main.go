package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	ctx := context.Background()

	_ = os.RemoveAll("./out")
	_ = os.MkdirAll("./out", 0700)

	senderDB, err := velocity.NewWithConfig(velocity.Config{Path: "./out/sender_db"})
	if err != nil {
		panic(err)
	}
	defer senderDB.Close()

	recipientDB, err := velocity.NewWithConfig(velocity.Config{Path: "./out/recipient_db"})
	if err != nil {
		panic(err)
	}
	defer recipientDB.Close()

	request := &velocity.EnvelopeRequest{
		Label:                "Production Envelope - Audit Chain Demo",
		Type:                 velocity.EnvelopeTypeCustodyProof,
		EvidenceClass:        "secret_bundle",
		CreatedBy:            "sender-ops",
		CaseReference:        "CASE-CHAIN-001",
		FingerprintSignature: "fp:sender-ops",
		IntakeLocation:       "sender-hq",
		Notes:                "sealed for recipient-only access",
		Payload: velocity.EnvelopePayload{
			Kind:            "secret",
			SecretReference: "ENV_SECRET",
			Metadata: map[string]string{
				"dependency_policy": "policy-prod-envelope",
				"dependency_file":   "incident.txt",
			},
		},
		Policies: velocity.EnvelopePolicies{
			Fingerprint: velocity.FingerprintPolicy{
				Required:               true,
				MatchingStrategy:       "exact",
				AuthorizedFingerprints: []string{"fp:recipient-secure"},
			},
			TimeLock: velocity.TimeLockPolicy{
				Mode:            "legal_delay",
				UnlockNotBefore: time.Now().Add(-1 * time.Minute),
				MinDelaySeconds: 0,
				LegalCondition:  "recipient-only",
			},
			ColdStorage: velocity.ColdStoragePolicy{Enabled: true, StorageClass: "audit-archive", Interval: "daily"},
			Tamper:      velocity.TamperPolicy{Analyzer: "velocity-ml-v1", Sensitivity: "high", Offline: true},
		},
		Tags: map[string]string{"env": "prod", "demo": "envelope-audit-chain"},
	}

	senderCtx := velocity.WithEnvelopeActor(ctx, "sender-ops")
	recipientCtx := velocity.WithEnvelopeActor(ctx, "recipient-secure")

	env, err := senderDB.CreateEnvelope(senderCtx, request)
	if err != nil {
		panic(err)
	}

	exportPath := filepath.Join("out", "secure-envelope.json")
	if err := senderDB.ExportEnvelope(senderCtx, env.EnvelopeID, exportPath); err != nil {
		panic(err)
	}

	imported, err := recipientDB.ImportEnvelope(recipientCtx, exportPath)
	if err != nil {
		panic(err)
	}

	// Recipient-only enforcement: reject non-recipient before access.
	if err := requireRecipientAccess(imported, "fp:attacker"); err == nil {
		panic("expected recipient-only access denial for attacker")
	}

	if err := requireRecipientAccess(imported, "fp:recipient-secure"); err != nil {
		panic(err)
	}

	finalEnv, err := recipientDB.LoadEnvelope(recipientCtx, imported.EnvelopeID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Envelope ID: %s\n", finalEnv.EnvelopeID)
	fmt.Printf("Custody logs: %d\n", len(finalEnv.CustodyLedger))
	fmt.Printf("Audit logs: %d\n", len(finalEnv.AuditLog))
	fmt.Printf("Tamper event logs: %d\n", len(finalEnv.TamperSignals))
	fmt.Printf("Recipient-only enforced for fingerprint: %s\n", "fp:recipient-secure")

	if err := verifyChainLinks(finalEnv); err != nil {
		panic(err)
	}
	if err := verifyAutoOperationLogs(finalEnv); err != nil {
		panic(err)
	}
	if err := runNegativeChecks(finalEnv, imported); err != nil {
		panic(err)
	}
	fmt.Println("Chain verification: OK")
	fmt.Println("Auto operation logging: OK")
	fmt.Println("Negative testing: OK")
}

func requireRecipientAccess(env *velocity.Envelope, fingerprint string) error {
	if env == nil {
		return fmt.Errorf("nil envelope")
	}
	if !env.Policies.Fingerprint.Required {
		return nil
	}
	for _, allowed := range env.Policies.Fingerprint.AuthorizedFingerprints {
		if allowed == fingerprint {
			return nil
		}
	}
	return fmt.Errorf("recipient-only check failed for %s", fingerprint)
}

func verifyAutoOperationLogs(env *velocity.Envelope) error {
	if env == nil {
		return fmt.Errorf("nil envelope")
	}
	hasAudit := map[string]bool{}
	for _, a := range env.AuditLog {
		hasAudit[a.Action] = true
	}
	for _, req := range []string{"envelope.init", "envelope.export", "envelope.import", "envelope.load"} {
		if !hasAudit[req] {
			return fmt.Errorf("missing automatic audit action %s", req)
		}
	}

	hasCustody := map[string]bool{}
	for _, c := range env.CustodyLedger {
		hasCustody[c.Action] = true
	}
	for _, req := range []string{"envelope.created", "envelope.exported", "envelope.imported", "envelope.loaded"} {
		if !hasCustody[req] {
			return fmt.Errorf("missing automatic custody action %s", req)
		}
	}
	return nil
}

func runNegativeChecks(finalEnv, imported *velocity.Envelope) error {
	if finalEnv == nil || imported == nil {
		return fmt.Errorf("nil envelope for negative tests")
	}

	// 1) Recipient-only negative check: unauthorized fingerprint must be denied.
	if err := requireRecipientAccess(imported, "fp:intruder"); err == nil {
		return fmt.Errorf("negative check failed: unauthorized recipient unexpectedly allowed")
	}

	// 2) Custody-chain tamper negative check: breaking prev hash must fail chain verification.
	tampered := *finalEnv
	tampered.CustodyLedger = append([]*velocity.CustodyEvent(nil), finalEnv.CustodyLedger...)
	if len(tampered.CustodyLedger) > 1 {
		e := *tampered.CustodyLedger[1]
		e.PrevHash = "tampered-prev-hash"
		tampered.CustodyLedger[1] = &e
		if err := verifyChainLinks(&tampered); err == nil {
			return fmt.Errorf("negative check failed: tampered custody chain passed verification")
		}
	}

	// 3) Audit-chain tamper negative check: breaking prev hash must fail verification.
	tamperedAudit := *finalEnv
	tamperedAudit.CustodyLedger = append([]*velocity.CustodyEvent(nil), finalEnv.CustodyLedger...)
	tamperedAudit.AuditLog = append([]*velocity.AuditEntry(nil), finalEnv.AuditLog...)
	if len(tamperedAudit.AuditLog) > 1 {
		e := *tamperedAudit.AuditLog[1]
		e.PrevHash = "tampered-audit-prev-hash"
		tamperedAudit.AuditLog[1] = &e
		if err := verifyChainLinks(&tamperedAudit); err == nil {
			return fmt.Errorf("negative check failed: tampered audit chain passed verification")
		}
	}

	return nil
}

func verifyChainLinks(env *velocity.Envelope) error {
	if env == nil {
		return fmt.Errorf("nil envelope")
	}
	for i := 1; i < len(env.CustodyLedger); i++ {
		prev := env.CustodyLedger[i-1]
		cur := env.CustodyLedger[i]
		if cur.PrevHash != prev.EventHash {
			return fmt.Errorf("custody chain broken at index %d", i)
		}
	}
	for i := 1; i < len(env.AuditLog); i++ {
		prev := env.AuditLog[i-1]
		cur := env.AuditLog[i]
		if cur.PrevHash != prev.EntryHash {
			return fmt.Errorf("audit chain broken at index %d", i)
		}
	}
	return nil
}

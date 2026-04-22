package velocity

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDataResidencyBlocksObjectWrite(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctm := db.ComplianceTagManager()
	if ctm == nil {
		t.Fatalf("compliance tag manager not initialized")
	}

	residency := NewDataResidencyManager(db)
	if err := residency.AddPolicy(ctx, &DataResidencyPolicy{
		PathPrefix: "/eu",
		Regions:    []string{"DE", "FR"},
		Framework:  "GDPR",
		Enabled:    true,
	}); err != nil {
		t.Fatalf("add residency policy: %v", err)
	}
	ctm.SetResidencyManager(residency)

	if err := ctm.TagPath(ctx, &ComplianceTag{
		Path:          "/eu",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassConfidential,
		EncryptionReq: true,
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag path: %v", err)
	}

	meta := map[string]string{
		"region":           "US",
		"subject_id":       "subject-1",
		"purpose":          "account_management",
		"mfa_verified":     "true",
		"crypto_algorithm": "AES-256-GCM",
	}

	_, err = db.StoreObject("/eu/transactions/txn-1.json", "application/json", "user",
		[]byte(`{"amount":100}`), &ObjectOptions{Encrypt: true, CustomMetadata: meta})
	if err == nil {
		t.Fatalf("expected residency violation")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "access denied") {
		// validateObjectCompliance returns ErrAccessDenied
		if !strings.Contains(strings.ToLower(err.Error()), "denied") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestBreachIncidentOnCriticalViolation(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	vm := NewViolationsManager(db)
	bns := NewBreachNotificationSystem(db)
	vm.SetBreachNotificationSystem(bns)

	violation := &ComplianceViolation{
		Actor:          "user",
		Path:           "/phi/record",
		Operation:      "read",
		Rules:          []string{"HIPAA Security Rule"},
		Frameworks:     []string{string(FrameworkHIPAA)},
		Severity:       "critical",
		DataClass:      string(DataClassRestricted),
		EncryptionUsed: false,
	}

	if err := vm.RecordViolation(ctx, violation); err != nil {
		t.Fatalf("record violation: %v", err)
	}

	// Wait for async breach reporting
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		keys, _ := db.Keys("breach:incident:*")
		if len(keys) > 0 {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("expected breach incident to be recorded")
}

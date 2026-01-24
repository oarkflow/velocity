package velocity

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPolicyPacksInstall(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	pe := NewPolicyEngine(db)
	if err := pe.InstallPolicyPack(ctx, PolicyPackGDPR); err != nil {
		t.Fatalf("install gdpr pack: %v", err)
	}
	if err := pe.InstallPolicyPack(ctx, PolicyPackHIPAA); err != nil {
		t.Fatalf("install hipaa pack: %v", err)
	}
	if err := pe.InstallPolicyPack(ctx, PolicyPackPCI); err != nil {
		t.Fatalf("install pci pack: %v", err)
	}

	policies, err := pe.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) == 0 {
		t.Fatalf("expected policies to be installed")
	}
}

func TestCompliancePutGetWithConsentAndMasking(t *testing.T) {
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

	tag := &ComplianceTag{
		Path:          "/users/email",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassConfidential,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "test",
	}
	if err := ctm.TagPath(ctx, tag); err != nil {
		t.Fatalf("tag path: %v", err)
	}

	req := &ComplianceOperationRequest{
		Path:        "/users/email/jane@example.com",
		Operation:   "write",
		Actor:       "app",
		SubjectID:   "subject-1",
		Purpose:     "account_management",
		Encrypted:   true,
		MFAVerified: true,
		Timestamp:   time.Now(),
	}

	// Without consent should fail
	if err := db.PutWithCompliance(ctx, req, []byte("jane@example.com")); err == nil {
		t.Fatalf("expected consent violation")
	}

	// Grant consent
	consent := NewConsentManager(db)
	if err := consent.GrantConsent(ctx, "subject-1", ConsentRecord{
		Purpose:         "account_management",
		GrantedAt:       time.Now(),
		LegalBasis:      "consent",
		ProcessingScope: []string{"email"},
		Active:          true,
	}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	ctm.SetConsentManager(consent)

	if err := db.PutWithCompliance(ctx, req, []byte("jane@example.com")); err != nil {
		t.Fatalf("put with consent: %v", err)
	}

	readReq := &ComplianceOperationRequest{
		Path:        "/users/email/jane@example.com",
		Operation:   "read",
		Actor:       "app",
		SubjectID:   "subject-1",
		Purpose:     "account_management",
		Encrypted:   true,
		MFAVerified: true,
		Timestamp:   time.Now(),
	}
	data, err := db.GetWithCompliance(ctx, readReq)
	if err != nil {
		t.Fatalf("get with compliance: %v", err)
	}
	if string(data) == "jane@example.com" {
		t.Fatalf("expected masked data, got original")
	}
	if !strings.Contains(string(data), "*") {
		t.Fatalf("expected masking to contain *")
	}
}

func TestRetentionAnonymizeObject(t *testing.T) {
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

	if err := ctm.TagPath(ctx, &ComplianceTag{
		Path:          "retention",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassConfidential,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag path: %v", err)
	}

	// Store without compliance checks since this is system operation
	_, err = db.StoreObject("retention/user.json", "application/json", "system",
		[]byte("jane@example.com"), &ObjectOptions{Encrypt: true, SystemOperation: true})
	if err != nil {
		t.Fatalf("store object: %v", err)
	}

	// Explicitly set compliance tag for retention testing
	tagMgr := db.ComplianceTagManager()
	if err := tagMgr.TagPath(ctx, &ComplianceTag{
		Path:       "retention/user.json",
		DataClass:  DataClassConfidential,
		Frameworks: []ComplianceFramework{FrameworkGDPR},
		CreatedAt:  time.Now(),
		CreatedBy:  "system",
	}); err != nil {
		t.Fatalf("set tag: %v", err)
	}

	// Add retention policy with very short retention period (1 millisecond)
	retention := NewRetentionManager(db)
	if err := retention.AddPolicy(ctx, RetentionPolicy{
		PolicyID:        "ret-anon",
		DataType:        string(DataClassConfidential),
		RetentionPeriod: 1 * time.Millisecond, // Very short period
		DeletionMethod:  "anonymize",
	}); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	// Wait for retention period to expire
	time.Sleep(5 * time.Millisecond)

	// Enforce retention - should anonymize the object
	processed, err := retention.EnforceRetentionActions(ctx)
	if err != nil {
		t.Fatalf("enforce retention: %v", err)
	}

	if processed == 0 {
		t.Fatalf("expected retention processing, got 0")
	}

	// Verify object was anonymized using internal API
	data, _, err := db.GetObjectInternal("retention/user.json", "test_service")
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	if string(data) == "jane@example.com" {
		t.Fatalf("expected anonymized data, got original data")
	}
}

func TestKeyRotationWorkflow(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	km := NewDataClassKeyManager(db)
	version, err := km.RotateKeyWithAudit(ctx, DataClassConfidential, NewAuditLogManager(db))
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if version < 2 {
		t.Fatalf("expected version >= 2, got %d", version)
	}
}

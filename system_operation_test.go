package velocity

import (
	"context"
	"testing"
)

func TestSystemOperationBypass(t *testing.T) {
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

	// Tag path with strict requirements
	if err := ctm.TagPath(ctx, &ComplianceTag{
		Path:          "/test",
		Frameworks:    []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		DataClass:     DataClassConfidential,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag path: %v", err)
	}

	// Test 1: Normal operation without encryption should fail
	req1 := &ComplianceOperationRequest{
		Path:            "/test/file.txt",
		Operation:       "write",
		Actor:           "user1",
		Encrypted:       false,
		SystemOperation: false,
	}
	result1, err := ctm.ValidateOperation(ctx, req1)
	if err != nil {
		t.Fatalf("validate operation: %v", err)
	}
	if result1.Allowed {
		t.Fatalf("expected operation to be blocked without encryption")
	}

	// Test 2: System operation without encryption should succeed
	req2 := &ComplianceOperationRequest{
		Path:            "/test/file.txt",
		Operation:       "write",
		Actor:           "system",
		Encrypted:       false,
		SystemOperation: true,
	}
	result2, err := ctm.ValidateOperation(ctx, req2)
	if err != nil {
		t.Fatalf("validate operation: %v", err)
	}
	if !result2.Allowed {
		t.Fatalf("expected system operation to be allowed, got: %v, reason: %s", result2.Allowed, result2.Reason)
	}
	if result2.Reason != "system operation - compliance checks bypassed" {
		t.Fatalf("unexpected reason: %s", result2.Reason)
	}

	// Test 3: Store object with SystemOperation flag should succeed
	_, err = db.StoreObject("/test/file.txt", "text/plain", "system",
		[]byte("test data"), &ObjectOptions{Encrypt: false, SystemOperation: true})
	if err != nil {
		t.Fatalf("store object with system operation: %v", err)
	}
}

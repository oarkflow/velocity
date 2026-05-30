package compliance_test

import (
	"context"
	. "github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/compliance"
	"strings"
	"testing"
	"time"
)

func TestComplianceResourceCanonicalAndInheritance(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	db, err := New(path)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctm := db.ComplianceTagManager()
	if err := ctm.TagResource(ctx, ComplianceResourceRef{Type: ComplianceResourceSQLSchema, SQLSchema: "main"}, &ComplianceTag{
		Frameworks: []compliance.Framework{compliance.FrameworkSOC2},
		DataClass:  compliance.DataClassInternal,
		CreatedBy:  "test",
	}); err != nil {
		t.Fatalf("tag schema: %v", err)
	}
	if err := ctm.TagResource(ctx, ComplianceResourceRef{Type: ComplianceResourceSQLTable, SQLTable: "patients"}, &ComplianceTag{
		Frameworks:    []compliance.Framework{compliance.FrameworkHIPAA},
		DataClass:     compliance.DataClassRestricted,
		EncryptionReq: true,
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag table: %v", err)
	}

	rowTag := ctm.GetResourceTag(ComplianceResourceRef{Type: ComplianceResourceSQLRow, SQLTable: "patients", SQLRowKey: "123"})
	if rowTag == nil {
		t.Fatalf("expected inherited row tag")
	}
	if !containsFramework(rowTag.Frameworks, compliance.FrameworkSOC2) || !containsFramework(rowTag.Frameworks, compliance.FrameworkHIPAA) {
		t.Fatalf("expected schema and table frameworks, got %#v", rowTag.Frameworks)
	}
	if !rowTag.EncryptionReq {
		t.Fatalf("expected inherited encryption requirement")
	}
	if canonicalID := (ComplianceResourceRef{Type: ComplianceResourceSQLRow, SQLTable: "patients", SQLRowKey: "patients:123"}).CanonicalID(); canonicalID != "sql:row:main.patients/123" {
		t.Fatalf("unexpected canonical row id: %s", canonicalID)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer reopened.Close()
	if tag := reopened.ComplianceTagManager().GetResourceTag(ComplianceResourceRef{Type: ComplianceResourceSQLTable, SQLTable: "patients"}); tag == nil {
		t.Fatalf("expected typed resource tag after reopen")
	}
}

func TestComplianceResourceBackwardCompatiblePathTags(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctm := db.ComplianceTagManager()
	if err := ctm.TagPath(ctx, &ComplianceTag{
		Path:          "/eu",
		Frameworks:    []compliance.Framework{compliance.FrameworkGDPR},
		DataClass:     compliance.DataClassConfidential,
		EncryptionReq: true,
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag path: %v", err)
	}

	result, err := ctm.ValidateResourceOperation(ctx, ComplianceResourceRef{Type: ComplianceResourceObject, Path: "/eu/reports/q1.txt"}, &ComplianceOperationRequest{
		Operation:   "write",
		Actor:       "app",
		Region:      "US",
		Encrypted:   false,
		MFAVerified: true,
		Timestamp:   time.Now(),
	})
	if err != nil {
		t.Fatalf("validate resource operation: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected inherited path tag to block object write")
	}
}

func TestComplianceSecretTags(t *testing.T) {
	ctx := context.Background()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctm := db.ComplianceTagManager()
	if err := ctm.TagResource(ctx, ComplianceResourceRef{Type: ComplianceResourceSecret, SecretName: "api-key"}, &ComplianceTag{
		Frameworks:    []compliance.Framework{compliance.FrameworkHIPAA},
		DataClass:     compliance.DataClassRestricted,
		EncryptionReq: true,
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag secret: %v", err)
	}

	if _, err := db.CreateSecret(ctx, SecretRequest{Name: "api-key", Value: []byte("secret"), Owner: "alice"}); err != nil {
		t.Fatalf("create secret should pass because secret records are encrypted: %v", err)
	}
	value, _, err := db.GetSecretValue(ctx, SecretRef{Name: "api-key"})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(value) != "secret" {
		t.Fatalf("unexpected secret value: %s", value)
	}

	if err := ctm.TagResource(ctx, ComplianceResourceRef{Type: ComplianceResourceSecret, SecretName: "blocked"}, &ComplianceTag{
		Frameworks:    []compliance.Framework{compliance.FrameworkPCIDSS},
		DataClass:     compliance.DataClassRestricted,
		EncryptionReq: true,
		CreatedBy:     "test",
	}); err != nil {
		t.Fatalf("tag blocked secret: %v", err)
	}
	_, err = db.CreateSecret(ctx, SecretRequest{Name: "blocked", Value: []byte("secret"), Owner: "alice"})
	if err == nil || !strings.Contains(err.Error(), "MFA") {
		t.Fatalf("expected PCI MFA compliance violation, got %v", err)
	}
}

//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"fmt"
	"github.com/oarkflow/velocity/pkg/auth"
	"github.com/oarkflow/velocity/pkg/compliance"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

// Enterprise Compliance Demo
// Demonstrates 20+ enterprise features: audit, RBAC, violations, reporting,
// consent, retention, masking, alerts, break-glass, key rotation, data residency,
// data discovery/classification, SoD, access reviews, lineage, policy packs.
func main() {
	ctx := context.Background()

	// Initialize DB
	db, err := velocity.New("./enterprise-compliance-demo-data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Compliance tag manager (auto-wired)
	ctm := db.ComplianceTagManager()

	// RBAC + SoD + Access Reviews
	rbac := auth.NewRBACManager(db)
	sod := auth.NewSoDManager()
	sod.AddPolicy(auth.SoDPolicy{
		PolicyID:          "sod-finance-admin",
		Name:              "Finance/Admin Separation",
		IncompatibleRoles: []string{auth.RoleSystemAdmin, "finance_admin"},
		Enabled:           true,
	})
	rbac.SetSoDManager(sod)

	reviews := auth.NewAccessReviewManager(db)
	rbac.SetAccessReviewManager(reviews)

	_ = rbac.AddUser(&auth.User{
		ID:       "u-100",
		Username: "bank-admin",
		Roles:    []string{auth.RoleSystemAdmin},
		Active:   true,
	})

	// Policy packs (GDPR/HIPAA/PCI)
	if ctm != nil {
		pe := velocity.NewPolicyEngine(db)
		_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackGDPR)
		_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackHIPAA)
		_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackPCI)
		ctm.SetPolicyEngine(pe)
	}

	// Data residency policy
	residency := velocity.NewDataResidencyManager(db)
	_ = residency.AddPolicy(ctx, &velocity.DataResidencyPolicy{
		PathPrefix: "/eu",
		Regions:    []string{"DE", "FR", "NL"},
		Framework:  "GDPR",
		Enabled:    true,
	})
	if ctm != nil {
		ctm.SetResidencyManager(residency)
	}

	// Break-glass workflow
	breakGlass := velocity.NewBreakGlassManager(db)
	if ctm != nil {
		ctm.SetBreakGlassManager(breakGlass)
	}
	bgReq := &velocity.BreakGlassRequest{
		Actor:    "bank-admin",
		Reason:   "Incident investigation",
		Resource: "/customers/ssn/jane-doe",
	}
	_ = breakGlass.RequestAccess(ctx, bgReq)
	_ = breakGlass.ApproveRequest(ctx, bgReq.RequestID, "security-officer")

	// Retention policies + scheduler
	retention := velocity.NewRetentionManager(db)
	_ = retention.AddPolicy(ctx, velocity.RetentionPolicy{
		PolicyID:        "pii-1y",
		DataType:        string(compliance.DataClassConfidential),
		RetentionPeriod: 365 * 24 * time.Hour,
		DeletionMethod:  "anonymize",
	})
	retention.StartRetentionScheduler(ctx, 12*time.Hour)
	if ctm != nil {
		ctm.SetRetentionManager(retention)
	}

	// Consent management (GDPR)
	consentMgr := compliance.NewConsentManager(db)
	_ = consentMgr.GrantConsent(ctx, "subject-123", compliance.ConsentRecord{
		Purpose:         "account_management",
		GrantedAt:       time.Now(),
		LegalBasis:      "consent",
		ProcessingScope: []string{"email", "address"},
		Active:          true,
	})
	if ctm != nil {
		ctm.SetConsentManager(consentMgr)
	}

	// Key rotation workflows
	krw := velocity.NewKeyRotationWorkflow(db)
	_, _ = krw.RotateClassKey(ctx, compliance.DataClassConfidential)

	// Tag paths with compliance requirements
	_ = ctm.TagPath(ctx, &velocity.ComplianceTag{
		Path:          "/customers",
		Frameworks:    []compliance.Framework{compliance.FrameworkGDPR},
		DataClass:     compliance.DataClassConfidential,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "dpo",
	})

	_ = ctm.TagPath(ctx, &velocity.ComplianceTag{
		Path:          "/eu/transactions",
		Frameworks:    []compliance.Framework{compliance.FrameworkPCIDSS},
		DataClass:     compliance.DataClassRestricted,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "security",
	})

	// Compliance-aware key/value operations
	_ = db.PutWithCompliance(ctx, &velocity.ComplianceOperationRequest{
		Path:        "/customers/email/jane@example.com",
		Operation:   "write",
		Actor:       "bank-admin",
		SubjectID:   "subject-123",
		Purpose:     "account_management",
		Encrypted:   true,
		MFAVerified: true,
		Region:      "DE",
		Timestamp:   time.Now(),
	}, []byte("jane@example.com"))

	_, _ = db.GetWithCompliance(ctx, &velocity.ComplianceOperationRequest{
		Path:        "/customers/email/jane@example.com",
		Operation:   "read",
		Actor:       "bank-admin",
		SubjectID:   "subject-123",
		Purpose:     "account_management",
		Encrypted:   true,
		MFAVerified: true,
		Region:      "DE",
		Timestamp:   time.Now(),
	})

	// Compliance-aware object storage
	objMeta := map[string]string{
		"region":                 "DE",
		"subject_id":             "subject-123",
		"purpose":                "account_management",
		"break_glass_request_id": bgReq.RequestID,
		"mfa_verified":           "true",
		"crypto_algorithm":       "AES-256-GCM",
	}

	_, _ = db.StoreObject("/eu/transactions/txn-001.json", "application/json", "bank-admin",
		[]byte(`{"amount":1200,"card":"4111-1111-1111-1111"}`),
		&velocity.ObjectOptions{Encrypt: true, CustomMetadata: objMeta})

	_, _, _ = db.GetObject("/eu/transactions/txn-001.json", "bank-admin")

	// Compliance reporting
	reporter := velocity.NewReportingManager(db, velocity.NewAuditLogManager(db), velocity.NewViolationsManager(db))
	report, _ := reporter.GenerateReport(ctx, "all", velocity.ReportPeriod{
		StartDate: time.Now().Add(-30 * 24 * time.Hour),
		EndDate:   time.Now(),
		Duration:  "monthly",
	}, "compliance-officer")
	fmt.Printf("Report ID: %s\n", report.ReportID)

	fmt.Println("Enterprise compliance demo complete.")
}

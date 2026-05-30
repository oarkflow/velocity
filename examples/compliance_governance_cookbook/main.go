package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	ctx := context.Background()
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: dir, MasterKey: []byte("0123456789abcdef0123456789abcdef")})
	check(err)
	defer db.Close()

	tags := velocity.NewComplianceTagManager(db)
	check(tags.TagPath(ctx, &velocity.ComplianceTag{
		Path:          "/records/customers",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR, velocity.FrameworkSOC2},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "privacy",
		Custodian:     "platform",
		RetentionDays: 365,
		EncryptionReq: true,
		AccessPolicy:  "gdpr-customer-data",
		CreatedBy:     "cookbook",
	}))
	check(tags.TagPath(ctx, &velocity.ComplianceTag{
		Path:          "/records/customers/card.txt",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "payments",
		EncryptionReq: true,
		CreatedBy:     "cookbook",
	}))

	denied, err := tags.ValidateOperation(ctx, &velocity.ComplianceOperationRequest{
		Path:      "/records/customers/card.txt",
		Operation: "write",
		Actor:     "alice",
		Encrypted: false,
	})
	check(err)
	allowed, err := tags.ValidateOperation(ctx, &velocity.ComplianceOperationRequest{
		Path:      "/records/customers/card.txt",
		Operation: "write",
		Actor:     "alice",
		Encrypted: true,
	})
	check(err)

	classifier := velocity.NewDataClassificationEngine(db)
	classification, err := classifier.ClassifyData(ctx, []byte("Jane Doe email jane@example.test card 4111111111111111"))
	check(err)
	masked := classifier.MaskData([]byte("Jane jane@example.test 4111111111111111"), classification)

	consent := velocity.NewConsentManager(db)
	check(consent.GrantConsent(ctx, "subject-1", velocity.ConsentRecord{
		ConsentID:       "marketing-v1",
		Purpose:         "marketing",
		LegalBasis:      "consent",
		ProcessingScope: []string{"email"},
		Version:         "v1",
	}))
	hasConsent, _, err := consent.HasActiveConsent(ctx, "subject-1", "marketing")
	check(err)

	retention := velocity.NewRetentionManager(db)
	check(retention.AddPolicy(ctx, velocity.RetentionPolicy{
		PolicyID:        "restricted-short",
		DataType:        string(velocity.DataClassRestricted),
		RetentionPeriod: time.Millisecond,
		DeletionMethod:  "anonymize",
		ReviewInterval:  time.Hour,
	}))
	exceeds, _, err := retention.EvaluateRetention(ctx, string(velocity.DataClassRestricted), time.Hour)
	check(err)

	residency := velocity.NewDataResidencyManager(db)
	check(residency.AddPolicy(ctx, &velocity.DataResidencyPolicy{
		PolicyID:   "eu-customers",
		PathPrefix: "/records/customers",
		Regions:    []string{"EU"},
		Framework:  string(velocity.FrameworkGDPR),
		Enabled:    true,
	}))
	residencyOK, _, err := residency.ValidateResidency(ctx, "/records/customers/card.txt", "EU")
	check(err)

	audit := velocity.NewAuditLogManager(db)
	check(audit.LogEvent(velocity.AuditEvent{
		Actor: "alice", Action: "write", Resource: "object", ResourceID: "/records/customers/card.txt",
		Result: "denied", Classification: velocity.DataClassRestricted,
		ComplianceTags: []velocity.ComplianceFramework{velocity.FrameworkGDPR, velocity.FrameworkPCIDSS},
		Severity:       "high",
	}))
	check(audit.SealBlock())

	breakGlass := velocity.NewBreakGlassManager(db)
	breakGlass.SetAuditManager(audit)
	bgReq := &velocity.BreakGlassRequest{RequestID: "bg-1", Actor: "oncall", Reason: "incident review", Resource: "/records/customers/card.txt"}
	check(breakGlass.RequestAccess(ctx, bgReq))
	check(breakGlass.ApproveRequest(ctx, "bg-1", "security"))
	bgActive, err := breakGlass.IsActive(ctx, "bg-1")
	check(err)

	violations := velocity.NewViolationsManager(db)
	check(violations.RecordFromValidation(ctx, &velocity.ComplianceOperationRequest{
		Path: "/records/customers/card.txt", Operation: "write", Actor: "alice", Encrypted: false,
	}, denied))
	stats, err := violations.GetViolationStats(ctx, &velocity.ViolationFilter{})
	check(err)

	reporter := velocity.NewReportingManager(db, audit, violations)
	report, err := reporter.GenerateReport(ctx, "all", velocity.ReportPeriod{
		StartDate: time.Now().Add(-time.Hour), EndDate: time.Now().Add(time.Hour), Duration: "daily",
	}, "cookbook")
	check(err)

	fmt.Printf("allowed encrypted=%t denied plaintext=%t rules=%d\n", allowed.Allowed, denied.Allowed, len(denied.ViolatedRules))
	fmt.Printf("classification=%s matches=%d masked=%q\n", classification.Classification, len(classification.Matches), string(masked))
	fmt.Printf("consent=%t retention_exceeds=%t residency=%t breakglass=%t violations=%d report=%s\n", hasConsent, exceeds, residencyOK, bgActive, stats.Total, report.ReportID)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_compliance_governance_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

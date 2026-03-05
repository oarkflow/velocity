# Enterprise Compliance Guide

This guide documents enterprise‑grade compliance features and how to use them together.

## What’s Included (20+ Features)

1. Immutable audit trail
2. Role‑based access control (RBAC)
3. Compliance violations database
4. Compliance reporting system
5. Consent management (GDPR)
6. Automatic retention enforcement (delete/archive/anonymize)
7. Data masking engine
8. Real‑time alerts + webhooks
9. Break‑glass access
10. Key management per data class
11. Geographic data residency
12. Data discovery/classification engine
13. Policy engine with rule packs
14. GDPR rights workflows
15. Breach notification workflows
16. Key rotation workflows
17. Access reviews/attestation
18. Segregation of duties (SoD)
19. Data lineage tracking
20. DLP/block‑on‑detect enforcement

## Quick Start

```go
ctx := context.Background()

db, _ := velocity.New("./data")
ctm := db.ComplianceTagManager()

// Install policy packs
pe := velocity.NewPolicyEngine(db)
_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackGDPR)
_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackHIPAA)
_ = pe.InstallPolicyPack(ctx, velocity.PolicyPackPCI)
ctm.SetPolicyEngine(pe)
```

## Compliance‑Aware Reads/Writes

```go
req := &velocity.ComplianceOperationRequest{
    Path:        "/customers/email/jane@example.com",
    Operation:   "write",
    Actor:       "bank-admin",
    SubjectID:   "subject-123",
    Purpose:     "account_management",
    Encrypted:   true,
    MFAVerified: true,
    Region:      "DE",
    Timestamp:   time.Now(),
}
_ = db.PutWithCompliance(ctx, req, []byte("jane@example.com"))
```

## Object Storage Enforcement

```go
meta := map[string]string{
    "region": "DE",
    "subject_id": "subject-123",
    "purpose": "account_management",
    "break_glass_request_id": "breakglass:...",
    "mfa_verified": "true",
}

_, _ = db.StoreObject("/eu/transactions/txn-001.json", "application/json", "bank-admin",
    []byte(`{"amount":1200}`),
    &velocity.ObjectOptions{Encrypt: true, CustomMetadata: meta})
```

## Retention Enforcement

```go
retention := velocity.NewRetentionManager(db)
_ = retention.AddPolicy(ctx, velocity.RetentionPolicy{
    PolicyID:        "pii-1y",
    DataType:        string(velocity.DataClassConfidential),
    RetentionPeriod: 365 * 24 * time.Hour,
    DeletionMethod:  "anonymize",
})
retention.StartRetentionScheduler(ctx, 12*time.Hour)
```

## Break‑Glass Access

```go
bg := velocity.NewBreakGlassManager(db)
req := &velocity.BreakGlassRequest{Actor: "bank-admin", Reason: "incident", Resource: "/customers/ssn/jane"}
_ = bg.RequestAccess(ctx, req)
_ = bg.ApproveRequest(ctx, req.RequestID, "security-officer")
```

## Key Rotation

```go
krw := velocity.NewKeyRotationWorkflow(db)
_, _ = krw.RotateClassKey(ctx, velocity.DataClassConfidential)
```

## Reporting

```go
reporter := velocity.NewReportingManager(db, velocity.NewAuditLogManager(db), velocity.NewViolationsManager(db))
report, _ := reporter.GenerateReport(ctx, "all", velocity.ReportPeriod{StartDate: time.Now().Add(-30*24*time.Hour), EndDate: time.Now(), Duration: "monthly"}, "compliance-officer")
fmt.Println(report.ReportID)
```

## Example Program

Run the full enterprise demo:

```
go run examples/enterprise_compliance_demo.go
```

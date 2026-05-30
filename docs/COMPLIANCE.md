# Compliance

Velocity includes compliance primitives and workflow managers. These are building blocks; deployments still need policy review, operational controls, and external validation.

For a cross-subsystem copy-paste set, see [Code And Command Cookbook](COOKBOOK.md). This page focuses on compliance-specific code and commands.

For an executable shell walkthrough that tags every supported resource type and verifies KV, object, secret, SQL, and CLI behavior, run:

```bash
./scripts/compliance_full_flow.sh
```

## Frameworks And Classification

Source types include:

- `compliance.Framework`
- `compliance.DataClassification`
- `compliance.ConsentRecord`
- `compliance.NewConsentManager`
- GDPR controller
- HIPAA controller
- NIST controller
- FIPS-related crypto helpers
- PCI-style compliance tag validation

Compliance tags can be attached to paths, inherited, updated, removed, listed by framework, and validated for read/write/delete/export-style operations.

Velocity now also supports typed compliance resources for KV records, objects, buckets, folders, secrets, secret versions, SQL schemas, SQL tables, SQL columns, and SQL rows. Path tags still work, but typed references are preferred when the resource is not naturally a file-like path.

Typed Go:

```go
err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{
	Type:     velocity.ComplianceResourceSQLColumn,
	SQLTable: "patients",
	SQLColumn: "ssn",
}, &velocity.ComplianceTag{
	Frameworks:    []compliance.Framework{compliance.FrameworkHIPAA},
	DataClass:     compliance.DataClassRestricted,
	EncryptionReq: true,
	CreatedBy:     "admin",
})
if err != nil {
	log.Fatal(err)
}

result, err := ctm.ValidateResourceOperation(ctx, velocity.ComplianceResourceRef{
	Type:     velocity.ComplianceResourceSQLRow,
	SQLTable: "patients",
	SQLRowKey: "123",
}, &velocity.ComplianceOperationRequest{
	Operation: "read",
	Actor:     "auditor",
	Encrypted: true,
})
```

CLI:

```bash
./velocity compliance tag --type sql_table --table patients --framework HIPAA --class restricted --encrypt
./velocity compliance tag --type sql_column --table patients --column ssn --framework HIPAA --class restricted --encrypt
./velocity compliance tag --type secret --name api-key --framework GDPR --class confidential --encrypt
./velocity compliance tag --type object --path reports/q1.pdf --framework SOC2 --class internal
./velocity compliance get --type sql_column --table patients --column ssn
./velocity compliance check --type sql_table --table patients --operation read --actor alice --encrypted
```

Inheritance is restrictive: schema tags apply to tables, rows, and columns; table tags apply to rows and columns; bucket/folder tags apply to objects; secret tags apply to versions; KV prefix tags apply to child keys.

Go:

```go
ctx := context.Background()

db, err := velocity.New("./compliance_data")
if err != nil {
	log.Fatal(err)
}
defer db.Close()

ctm := velocity.NewComplianceTagManager(db)
db.SetComplianceTagManager(ctm)

err = ctm.TagPath(ctx, &velocity.ComplianceTag{
	Path:          "/patients",
	Frameworks:    []compliance.Framework{compliance.FrameworkHIPAA, compliance.FrameworkGDPR},
	DataClass:     compliance.DataClassRestricted,
	Owner:         "privacy",
	Custodian:     "platform",
	RetentionDays: 2555,
	EncryptionReq: true,
	AuditLevel:    "high",
	CreatedBy:     "admin",
})
if err != nil {
	log.Fatal(err)
}

tag := ctm.GetTag("/patients/123")
fmt.Println(tag.Path, tag.Frameworks, tag.DataClass)
```

Command:

```bash
go run ./examples/compliance_demo
go test -run 'TestComplianceTagManager_TagPath|TestComplianceTagManager_Inheritance|TestComplianceTagManager_MultiFramework' .
```

## Compliance-Aware Operations

The DB exposes:

- `PutWithCompliance`
- `GetWithCompliance`
- `DeleteWithCompliance`
- `SetComplianceTagManager`
- `ComplianceTagManager`
- `TagResource`
- `GetResourceTag`
- `GetResourceTags`
- `RemoveResourceTag`
- `ValidateResourceOperation`

These route operations through compliance validation and classification behavior.

Go:

```go
writeReq := &velocity.ComplianceOperationRequest{
	Path:            "/patients/123",
	Operation:       "write",
	Actor:           "nurse.alice",
	IPAddress:       "10.0.0.10",
	Region:          "US",
	SubjectID:       "patient-123",
	Purpose:         "treatment",
	Encrypted:       true,
	MFAVerified:     true,
	CryptoAlgorithm: "AES-256-GCM",
}

result, err := ctm.ValidateOperation(ctx, writeReq)
if err != nil {
	log.Fatal(err)
}
if !result.Allowed {
	log.Fatalf("blocked: %v", result.ViolatedRules)
}

err = db.PutWithCompliance(ctx, writeReq, []byte("MRN: 123456 diagnosis note"))
if err != nil {
	log.Fatal(err)
}

readReq := &velocity.ComplianceOperationRequest{
	Path:      "/patients/123",
	Operation: "read",
	Actor:     "nurse.alice",
	Region:    "US",
	SubjectID: "patient-123",
	Purpose:   "treatment",
}
masked, err := db.GetWithCompliance(ctx, readReq)
if err != nil {
	log.Fatal(err)
}
fmt.Println(string(masked))
```

Command:

```bash
go test -run 'TestCompliancePutGetWithConsentAndMasking|TestComplianceTagManager_ValidateOperation_GDPR|TestComplianceTagManager_ValidateOperation_HIPAA' .
```

## GDPR-Oriented Features

Available building blocks include:

- Consent records and consent manager.
- Data subject records and data subject requests.
- Processing activities.
- GDPR data export structures.
- Retention and anonymization helpers.
- Breach notification structures.

Go:

```go
import "github.com/oarkflow/velocity/pkg/compliance"

gdpr := velocity.NewGDPRController(db)

consent := compliance.ConsentRecord{
	ConsentID:       "consent-123",
	Purpose:         "treatment",
	GrantedAt:       time.Now(),
	LegalBasis:      "consent",
	ProcessingScope: []string{"patient_record"},
	Version:          "v1",
	Active:          true,
}

_ = gdpr.GrantConsent(ctx, "patient-123", consent)
ok, activeConsent, err := gdpr.HasActiveConsent(ctx, "patient-123", "treatment")
if err != nil {
	log.Fatal(err)
}
fmt.Println(ok, activeConsent.ConsentID)
```

Standalone consent manager:

```go
consents := compliance.NewConsentManager(db)
_ = consents.GrantConsent(ctx, "patient-123", compliance.ConsentRecord{
	Purpose:         "research",
	GrantedAt:       time.Now(),
	LegalBasis:      "consent",
	ProcessingScope: []string{"analytics"},
	Active:          true,
})
```

Command:

```bash
go run ./examples/compliance_full_demo
go run ./examples/compliance_governance_cookbook
```

## HIPAA-Oriented Features

Available building blocks include:

- Business associate records.
- PHI detector and PHI patterns.
- Minimum necessary enforcement.
- HIPAA audit controls.
- Access limits.

Go:

```go
hipaaReq := &velocity.ComplianceOperationRequest{
	Path:            "/patients/123",
	Operation:       "read",
	Actor:           "nurse.alice",
	Region:          "US",
	SubjectID:       "patient-123",
	Purpose:         "treatment",
	Encrypted:       true,
	MFAVerified:     true,
	CryptoAlgorithm: "AES-256-GCM",
}

result, err := ctm.ValidateOperation(ctx, hipaaReq)
if err != nil {
	log.Fatal(err)
}
fmt.Println(result.Allowed, result.RequiredActions)
```

Command:

```bash
go test -run 'TestComplianceTagManager_ValidateOperation_HIPAA' .
```

## Governance And Reporting

Managers and structures cover:

- Compliance reports and report periods.
- Compliance summaries.
- Audit statistics.
- Data inventory summaries.
- Path access and actor activity.
- Retention alerts.
- Violations and alert managers.
- Webhook configs and rate limiting.
- Policy packs.

Go:

```go
audit := velocity.NewAuditLogManager(db)
violations := velocity.NewViolationsManager(db)
reports := velocity.NewReportingManager(db, audit, violations)

report, err := reports.GenerateReport(ctx, "all", velocity.ReportPeriod{
	StartDate: time.Now().Add(-30 * 24 * time.Hour),
	EndDate:   time.Now(),
	Duration:  "monthly",
}, "auditor")
if err != nil {
	log.Fatal(err)
}

data, err := reports.ExportReport(ctx, report, "json")
if err != nil {
	log.Fatal(err)
}
fmt.Println(string(data))
```

Command:

```bash
go test -run 'TestPolicyPacksInstall|TestBreachIncidentOnCriticalViolation' .
```

## Data Controls

Velocity includes managers for:

- Data classification.
- Data masking.
- Data residency.
- Data lineage.
- Retention policies.
- Legal holds.
- Breach incidents.
- Key rotation workflows.

Retention Go:

```go
retention := velocity.NewRetentionManager(db)
_ = retention.AddPolicy(ctx, velocity.RetentionPolicy{
	PolicyID:        "restricted-7y",
	DataType:        string(compliance.DataClassRestricted),
	RetentionPeriod: 7 * 365 * 24 * time.Hour,
	DeletionMethod:  "cryptographic_erase",
	ReviewInterval:  90 * 24 * time.Hour,
})

expired, policy, err := retention.EvaluateRetention(ctx, string(compliance.DataClassRestricted), 8*365*24*time.Hour)
if err != nil {
	log.Fatal(err)
}
fmt.Println(expired, policy.PolicyID)
```

Residency Go:

```go
residency := velocity.NewDataResidencyManager(db)
_ = residency.AddPolicy(ctx, &velocity.DataResidencyPolicy{
	PathPrefix: "/patients",
	Regions:    []string{"US"},
	Framework:  string(compliance.FrameworkHIPAA),
	Enabled:    true,
})

allowed, matched, err := residency.ValidateResidency(ctx, "/patients/123", "EU")
if err != nil {
	log.Fatal(err)
}
fmt.Println(allowed, matched.PolicyID)
```

Masking and lineage Go:

```go
masking := velocity.NewDataMaskingEngine()
masked := masking.MaskString("alice@example.test SSN 123-45-6789", compliance.DataClassRestricted)
fmt.Println(masked)

lineage := velocity.NewLineageManager(db)
_ = lineage.RecordEvent(ctx, &velocity.LineageEvent{
	Path:   "/patients/123",
	Action: "read",
	Actor:  "nurse.alice",
})
events, _ := lineage.GetLineage(ctx, "/patients/123")
fmt.Println(len(events))
```

Command:

```bash
go test -run 'TestRetentionAnonymizeObject|TestDataResidencyBlocksObjectWrite|TestKeyRotationWorkflow' .
```

## Operational Guidance

- Treat framework support as implementation support, not certification.
- Document which managers are initialized by your app.
- Keep audit exports and backup integrity outputs with incident records.
- Validate compliance tags in tests for your path model.
- Avoid benchmark-only durability/security flags in regulated workflows.

## Command Availability

The current shipped binary from `cmd/velocity` does not include a `compliance` command. Use these command forms today:

```bash
go run ./examples/compliance_demo
go run ./examples/compliance_full_demo
go run ./examples/compliance_governance_cookbook
go run ./examples/enterprise_compliance_demo
go test -run 'TestComplianceTagManager|TestCompliancePutGetWithConsentAndMasking|TestRetentionAnonymizeObject' .
```

For HTTP-accessible governance, the enterprise API exposes IAM, STS, metrics, lifecycle, notification, integrity, and cluster routes when `EnterpriseAPI.RegisterRoutes` is wired by the host app. Example IAM evaluation command shape:

```bash
curl -X POST http://localhost:8081/api/v1/iam/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"principal":"alice","action":"object:GetObject","resource":"patients/123"}'
```

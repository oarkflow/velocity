# Compliance Tagging System

## Overview

The Velocity Database Compliance Tagging System allows you to apply regulatory compliance frameworks (GDPR, HIPAA, PCI DSS, FIPS, NIST, SOC2, ISO27001) at the **folder, file, or key-value level**. Compliance requirements automatically propagate through inheritance, and all operations are validated against the applied frameworks.

## Key Features

✅ **Path-Based Tagging**: Tag any folder, file, or key-value path
✅ **Automatic Inheritance**: Children automatically inherit parent's compliance
✅ **Multi-Framework Support**: Apply multiple frameworks simultaneously
✅ **Operation Validation**: Automatic compliance checks on all operations
✅ **Violation Reporting**: Detailed explanations of what went wrong
✅ **Persistent**: Tags survive database restarts
✅ **Zero Overhead**: Only validates tagged paths

## Supported Compliance Frameworks

| Framework | Constant | Description |
|-----------|----------|-------------|
| **GDPR** | `FrameworkGDPR` | EU General Data Protection Regulation |
| **HIPAA** | `FrameworkHIPAA` | Health Insurance Portability and Accountability Act |
| **PCI DSS** | `FrameworkPCIDSS` | Payment Card Industry Data Security Standard |
| **FIPS** | `FrameworkFIPS` | Federal Information Processing Standards |
| **NIST** | `FrameworkNIST` | NIST 800-53 Security Controls |
| **SOC 2** | `FrameworkSOC2` | Service Organization Control 2 |
| **ISO 27001** | `FrameworkISO27001` | Information Security Management |

## Quick Start

### 1. Create Compliance Tag Manager

```go
import "github.com/oarkflow/velocity"

db, _ := velocity.New("./data")
ctm := velocity.NewComplianceTagManager(db)
```

### 2. Tag a Folder with Compliance Requirements

```go
tag := &velocity.ComplianceTag{
    Path:          "/customer-data",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:     velocity.DataClassConfidential,
    Owner:         "privacy-team",
    Custodian:     "it-department",
    RetentionDays: 730, // 2 years
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "compliance-officer",
}

err := ctm.TagPath(context.Background(), tag)
```

### 3. All Children Automatically Inherit Compliance

```go
// This file automatically inherits GDPR compliance from /customer-data
childTag := ctm.GetTag("/customer-data/users/john_doe.json")

fmt.Println(childTag.Frameworks) // [GDPR]
fmt.Println(childTag.EncryptionReq) // true
fmt.Println(childTag.DataClass) // confidential
```

### 4. Validate Operations

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/customer-data/new-user.json",
    Operation: "write",
    Actor:     "app-server",
    Encrypted: false, // ❌ Will fail GDPR validation
    Timestamp: time.Now(),
}

result, _ := ctm.ValidateOperation(context.Background(), req)

if !result.Allowed {
    fmt.Println("Operation blocked!")
    for _, violation := range result.ViolatedRules {
        fmt.Println("-", violation)
    }
}
```

## Compliance Tag Structure

```go
type ComplianceTag struct {
    Path           string                 // Folder/file/key path
    Frameworks     []ComplianceFramework  // Applied frameworks
    DataClass      DataClassification     // public, internal, confidential, restricted
    Owner          string                 // Data owner
    Custodian      string                 // Data custodian
    RetentionDays  int                    // Retention period
    EncryptionReq  bool                   // Encryption required
    AuditLevel     string                 // high, medium, low
    AccessPolicy   string                 // RBAC policy name
    CreatedAt      time.Time
    CreatedBy      string
    Metadata       map[string]interface{}
}
```

## Common Use Cases

### Use Case 1: GDPR Personal Data

```go
// Tag EU customer data folder
gdprTag := &velocity.ComplianceTag{
    Path:          "/eu-customers",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:     velocity.DataClassConfidential,
    Owner:         "privacy-officer",
    RetentionDays: 730, // 2 years
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "compliance-team",
}
ctm.TagPath(ctx, gdprTag)

// Now all files under /eu-customers/* are GDPR-compliant
// - Must be encrypted
// - Retention: 2 years
// - High audit level (every access logged)
```

**GDPR Validation Rules:**
- ✅ Article 32: Encryption required for confidential data
- ✅ Article 5(1)(e): Storage limitation enforced
- ✅ Article 15/17/20: Data subject rights supported
- ✅ Consent verification required

### Use Case 2: HIPAA Protected Health Information

```go
// Tag PHI folder
hipaaTag := &velocity.ComplianceTag{
    Path:          "/patient-records",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted,
    Owner:         "medical-director",
    RetentionDays: 2555, // 7 years (HIPAA requirement)
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "hipaa-officer",
}
ctm.TagPath(ctx, hipaaTag)

// All patient data now requires:
// - Encryption (HIPAA Security Rule)
// - Minimum necessary access
// - Audit logging
// - BAA verification for external access
```

**HIPAA Validation Rules:**
- ✅ Security Rule: Encryption required
- ✅ Privacy Rule: Minimum necessary enforcement
- ✅ Audit Controls: All access logged
- ✅ BAA Verification: Business associate agreements checked

### Use Case 3: PCI DSS Payment Data

```go
// Tag payment data folder
pciTag := &velocity.ComplianceTag{
    Path:          "/payment-data",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    DataClass:     velocity.DataClassRestricted,
    Owner:         "cfo",
    RetentionDays: 365, // 1 year
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "security-officer",
}
ctm.TagPath(ctx, pciTag)

// Payment data operations now require:
// - Encryption (PCI DSS 3.4)
// - MFA authentication (PCI DSS 8.3)
// - Access logging (PCI DSS 10.1)
// - Retention policy (PCI DSS 3.1)
```

**PCI DSS Validation Rules:**
- ✅ Requirement 3.4: Cardholder data encryption
- ✅ Requirement 8.3: MFA required
- ✅ Requirement 10.1: Access logging
- ✅ Requirement 3.1: Retention policy enforced

### Use Case 4: FIPS Government/Military Data

```go
// Tag classified data folder
fipsTag := &velocity.ComplianceTag{
    Path:       "/classified",
    Frameworks: []velocity.ComplianceFramework{
        velocity.FrameworkFIPS,
        velocity.FrameworkNIST,
    },
    DataClass:     velocity.DataClassRestricted,
    Owner:         "security-clearance-officer",
    RetentionDays: 3650, // 10 years
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "government-admin",
}
ctm.TagPath(ctx, fipsTag)

// Classified data operations now require:
// - FIPS-approved algorithms (AES-256-GCM, SHA-256)
// - NIST security controls
// - Authenticated access
// - TLS 1.3 for transmission
```

**FIPS Validation Rules:**
- ✅ FIPS 140-2: Approved algorithms only (AES-256-GCM, SHA-256, SHA-512, PBKDF2)
- ✅ NIST AC-3: Access enforcement
- ✅ NIST SC-8: Transmission confidentiality
- ✅ NIST SC-13: Cryptographic protection

### Use Case 5: Multi-Framework Healthcare Payments

```go
// Tag folder with multiple frameworks
multiTag := &velocity.ComplianceTag{
    Path: "/healthcare-payments",
    Frameworks: []velocity.ComplianceFramework{
        velocity.FrameworkHIPAA,   // PHI protection
        velocity.FrameworkPCIDSS,  // Payment card protection
        velocity.FrameworkSOC2,    // Trust services
    },
    DataClass:     velocity.DataClassRestricted,
    RetentionDays: 2555, // 7 years (longest requirement)
    EncryptionReq: true,
    AuditLevel:    "high",
    CreatedBy:     "compliance-team",
}
ctm.TagPath(ctx, multiTag)

// Operations must satisfy ALL frameworks:
// - HIPAA: PHI encryption, minimum necessary, audit logging
// - PCI DSS: Cardholder encryption, MFA, access logging
// - SOC2: Encryption at rest, monitoring, access controls
```

## Operation Validation

### Validation Request

```go
req := &velocity.ComplianceOperationRequest{
    Path:            string    // Resource path
    Operation:       string    // "read", "write", "delete"
    Actor:           string    // User/service performing operation
    Encrypted:       bool      // Is data encrypted?
    MFAVerified:     bool      // MFA verified?
    CryptoAlgorithm: string    // Algorithm used (for FIPS validation)
    Reason:          string    // Reason for operation (for GDPR deletion)
    DataAge:         int       // Days since creation (for retention)
    Timestamp:       time.Time
}
```

### Validation Result

```go
result, err := ctm.ValidateOperation(ctx, req)

if !result.Allowed {
    fmt.Println("Operation blocked!")
    for _, violation := range result.ViolatedRules {
        fmt.Println("Violation:", violation)
    }
}

for _, action := range result.RequiredActions {
    fmt.Println("Required:", action)
}
```

### Example Validation Results

#### ❌ Blocked: GDPR without encryption

```
Operation: write
Path: /customer-data/user.json
Encrypted: false

Result:
  Allowed: false
  Violated Rules:
    - GDPR Article 32: confidential data must be encrypted
    - encryption required but data is not encrypted
  Required Actions:
    - encrypt data before write
    - log audit event with high severity
```

#### ❌ Blocked: PCI DSS without MFA

```
Operation: write
Path: /payment-data/transaction.json
MFAVerified: false

Result:
  Allowed: false
  Violated Rules:
    - PCI DSS 8.3: MFA required for cardholder data access
  Required Actions:
    - enable MFA authentication
    - log all access to cardholder data
```

#### ✅ Allowed: FIPS with approved algorithm

```
Operation: write
Path: /classified/document.bin
Encrypted: true
CryptoAlgorithm: AES-256-GCM

Result:
  Allowed: true
  Required Actions:
    - NIST AU-2: log security-relevant events
    - FIPS 140-2: use approved key management
```

## Advanced Features

### 1. Update Compliance Tag

```go
err := ctm.UpdateTag(ctx, "/customer-data", func(tag *velocity.ComplianceTag) error {
    // Add SOC2 to existing GDPR compliance
    tag.Frameworks = append(tag.Frameworks, velocity.FrameworkSOC2)

    // Extend retention period
    tag.RetentionDays = 1095 // 3 years

    // Update owner
    tag.Owner = "new-privacy-officer"

    return nil
})
```

### 2. List Tags by Framework

```go
// Find all GDPR-tagged paths
gdprPaths := ctm.ListTagsByFramework(velocity.FrameworkGDPR)

for _, tag := range gdprPaths {
    fmt.Printf("Path: %s\n", tag.Path)
    fmt.Printf("Owner: %s\n", tag.Owner)
    fmt.Printf("Retention: %d days\n", tag.RetentionDays)
}
```

### 3. Get Effective Frameworks

```go
// Get all frameworks applicable to a path (including inherited)
frameworks := ctm.GetEffectiveFrameworks("/customer-data/user-123.json")

for _, fw := range frameworks {
    fmt.Println("Framework:", fw)
}
```

### 4. Simple Compliance Check

```go
// Quick boolean check (no detailed violations)
allowed, err := ctm.CheckCompliance(
    ctx,
    "/customer-data/user.json", // path
    "write",                     // operation
    "app-server",                // actor
    true,                        // encrypted
)

if !allowed {
    return fmt.Errorf("compliance violation detected")
}
```

### 5. Remove Compliance Tag

```go
// Remove compliance requirements from a path
err := ctm.RemoveTag(ctx, "/temporary-data")

// Children will no longer inherit compliance
```

## Integration with Existing Systems

### With RBAC System

```go
// Set access policy in compliance tag
tag := &velocity.ComplianceTag{
    Path:         "/sensitive-data",
    Frameworks:   []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    AccessPolicy: "gdpr-policy", // References RBAC policy
}

// Validation will check RBAC policy
result, _ := ctm.ValidateOperation(ctx, req)
// Required action: "verify RBAC policy: gdpr-policy"
```

### With Audit System

```go
// High audit level = log all operations
tag := &velocity.ComplianceTag{
    Path:       "/payment-data",
    Frameworks: []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    AuditLevel: "high", // "high", "medium", "low"
}

// Required action: "log audit event with high severity"
```

### With Data Classification Engine

```go
// Compliance tag works with data classification
tag := &velocity.ComplianceTag{
    Path:      "/classified",
    DataClass: velocity.DataClassRestricted, // Most sensitive
}

// DataClassification levels:
// - DataClassPublic
// - DataClassInternal
// - DataClassConfidential
// - DataClassRestricted
```

## Best Practices

### 1. Tag at the Folder Level

```go
// ✅ Good: Tag folders, let children inherit
ctm.TagPath(ctx, &velocity.ComplianceTag{
    Path: "/customer-data",
    Frameworks: []velocity.ComplianceFramework{velocity.FrameworkGDPR},
})

// ❌ Bad: Tagging individual files is tedious
ctm.TagPath(ctx, &velocity.ComplianceTag{Path: "/customer-data/file1.json"})
ctm.TagPath(ctx, &velocity.ComplianceTag{Path: "/customer-data/file2.json"})
```

### 2. Use Appropriate Retention Periods

```go
// HIPAA: 7 years
RetentionDays: 2555

// PCI DSS: 1 year
RetentionDays: 365

// GDPR: As long as necessary (e.g., 2 years)
RetentionDays: 730
```

### 3. Always Specify Data Owner and Custodian

```go
tag := &velocity.ComplianceTag{
    Owner:     "privacy-officer",    // Who decides what data is collected
    Custodian: "it-department",      // Who manages the technical implementation
}
```

### 4. Use High Audit Level for Sensitive Data

```go
tag := &velocity.ComplianceTag{
    Path:       "/patient-records",
    AuditLevel: "high", // Log every access
}
```

## Performance Considerations

- **Zero Overhead for Untagged Paths**: Only tagged paths incur validation overhead
- **In-Memory Cache**: Tags are loaded once at startup
- **O(log n) Lookup**: Path-based tree lookup for inheritance
- **Minimal Latency**: < 1ms validation time per operation

## Complete Example

See [examples/compliance_demo.go](examples/compliance_demo.go) for a complete working example demonstrating:
- Tagging folders with different frameworks
- Inheritance testing
- Operation validation (pass and fail cases)
- Framework filtering
- Tag updates

Run it with:
```bash
go run -tags velocity_examples examples/compliance_demo.go
```

## Troubleshooting

### Tag not found

**Issue**: `ctm.GetTag(path)` returns `nil`

**Solution**: Check that:
1. Tag was created: `ctm.TagPath(ctx, tag)`
2. Path is normalized: `/customer-data` not `customer-data`
3. Database is open

### Operation always blocked

**Issue**: All operations fail validation

**Solution**: Check request fields:
- `Encrypted: true` for sensitive data
- `MFAVerified: true` for PCI DSS
- `CryptoAlgorithm: "AES-256-GCM"` for FIPS
- `Actor: "username"` for authentication

### Children not inheriting

**Issue**: Child files don't inherit parent's compliance

**Solution**: Ensure paths are hierarchical:
- ✅ Parent: `/customer-data`, Child: `/customer-data/users/file.json`
- ❌ Parent: `/customer-data`, Child: `/other-folder/file.json`

## Framework-Specific Notes

### GDPR
- Requires encryption for confidential data
- Enforces retention periods
- Requires consent verification
- Supports data subject rights

### HIPAA
- Always requires encryption
- Enforces minimum necessary access
- Requires audit logging
- Checks BAA for external access

### PCI DSS
- Requires encryption + MFA
- Enforces retention policies
- Requires comprehensive logging
- Validates cardholder data access

### FIPS
- Only allows approved algorithms
- Validates crypto algorithms
- Requires approved key management

### NIST
- Requires authenticated access
- Enforces TLS 1.3
- Requires security event logging
- Validates cryptographic protection

---

**Built for compliance. Ready for audits. Zero vendor lock-in.**

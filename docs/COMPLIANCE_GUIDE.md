# Compliance Tagging Guide

## Overview

Velocity's compliance tagging system allows you to apply regulatory compliance requirements (HIPAA, GDPR, PCI DSS, SOC2, FIPS) to your data at three levels:
1. **Folders** - Apply to entire directory trees
2. **Keys** - Apply to specific key-value pairs
3. **Files** - Apply to file storage paths

All operations (store, get, update, delete) are validated against compliance rules **before** execution.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Scenario 1: Folder Compliance](#scenario-1-folder-compliance-hipaaphi)
- [Scenario 2: Key Compliance](#scenario-2-key-compliance-gdprpii)
- [Scenario 3: File Compliance](#scenario-3-file-compliance-pci-dss)
- [Compliance Frameworks](#compliance-frameworks)
- [Data Classifications](#data-classifications)
- [Validation Flow](#validation-flow)
- [API Reference](#api-reference)

---

## Quick Start

```go
import "github.com/oarkflow/velocity"

db, _ := velocity.New("./data")
ctm := velocity.NewComplianceTagManager(db)
ctx := context.Background()

// Tag a path
tag := &velocity.ComplianceTag{
    Path:          "/healthcare/patients",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted,
    EncryptionReq: true,
    MFARequired:   true,
}
ctm.TagPath(ctx, tag)

// Validate an operation
req := &velocity.ComplianceOperationRequest{
    Path:        "/healthcare/patients/P123.json",
    Operation:   "write",
    Actor:       "nurse-station-1",
    Encrypted:   true,
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    db.Set([]byte(req.Path), data)
}
```

---

## Scenario 1: Folder Compliance (HIPAA/PHI)

### Problem
You need to store Protected Health Information (PHI) and ensure all operations comply with HIPAA regulations.

### Solution
Tag the folder with HIPAA compliance requirements.

### Example

```go
// 1. Tag the folder
healthcareTag := &velocity.ComplianceTag{
    Path:          "/healthcare",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted, // PHI is restricted
    RetentionDays: 2555,                          // 7 years (HIPAA requirement)
    EncryptionReq: true,                          // Must encrypt PHI
    MFARequired:   true,                          // Require MFA
    AuditLevel:    "high",
    Owner:         "healthcare-compliance-team",
}
ctm.TagPath(ctx, healthcareTag)

// 2. Prepare patient data
patientData := map[string]interface{}{
    "patient_id":      "P123456",
    "name":            "John Doe",
    "ssn":             "123-45-6789",
    "medical_history": "Diabetes Type 2",
}
patientJSON, _ := json.Marshal(patientData)
```

### STORE (Write) Operation

```go
// Without encryption - FAILS
writeReq := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123456.json",
    Operation: "write",
    Actor:     "nurse-station-1",
    Encrypted: false, // ❌ Not encrypted
}
result, _ := ctm.ValidateOperation(ctx, writeReq)
// result.Allowed = false
// result.ViolatedRules = ["HIPAA Security Rule: PHI must be encrypted"]

// With encryption - SUCCEEDS
writeReq.Encrypted = true
writeReq.MFAVerified = true
result, _ = ctm.ValidateOperation(ctx, writeReq)
// result.Allowed = true
if result.Allowed {
    db.Set([]byte(writeReq.Path), patientJSON)
}
```

**What Happens:**
- ✅ Validates encryption requirement
- ✅ Checks MFA verification
- ✅ Records audit event (high severity)
- ✅ Blocks operation if requirements not met
- ✅ Returns specific violations and required actions

### GET (Read) Operation

```go
readReq := &velocity.ComplianceOperationRequest{
    Path:        "/healthcare/patients/P123456.json",
    Operation:   "read",
    Actor:       "dr-smith",
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, readReq)
// result.Allowed = true
// result.RequiredActions = [
//     "enforce minimum necessary access for PHI",
//     "verify MFA for PHI access",
//     "log audit event with high severity"
// ]

if result.Allowed {
    data, _ := db.Get([]byte(readReq.Path))
    // Use data...
}
```

**What Happens:**
- ✅ Validates MFA requirement
- ✅ Enforces "minimum necessary" access (HIPAA Privacy Rule)
- ✅ Requires audit logging
- ✅ Returns actions to implement

### UPDATE Operation

```go
updateReq := &velocity.ComplianceOperationRequest{
    Path:        "/healthcare/patients/P123456.json",
    Operation:   "write",
    Actor:       "dr-smith",
    Encrypted:   true,
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, updateReq)

if result.Allowed {
    // Update the data
    patientData["last_visit"] = "2026-01-24"
    updatedJSON, _ := json.Marshal(patientData)
    db.Set([]byte(updateReq.Path), updatedJSON)
}
```

**What Happens:**
- ✅ Same validation as write operation
- ✅ Ensures encrypted updates
- ✅ Tracks modification in audit log

### DELETE Operation

```go
// Without reason - WARNING
deleteReq := &velocity.ComplianceOperationRequest{
    Path:        "/healthcare/patients/P123456.json",
    Operation:   "delete",
    Actor:       "compliance-officer",
    MFAVerified: true,
    Reason:      "", // ❌ No reason
}
result, _ := ctm.ValidateOperation(ctx, deleteReq)
// result.Allowed = true (allowed but with warnings)
// result.RequiredActions = ["verify MFA for PHI access", "log deletion reason"]

// With proper reason - CLEAN
deleteReq.Reason = "Patient requested data deletion under HIPAA Privacy Rule"
result, _ = ctm.ValidateOperation(ctx, deleteReq)
if result.Allowed {
    db.Delete([]byte(deleteReq.Path))
}
```

**What Happens:**
- ✅ Requires deletion reason for audit trail
- ✅ Validates MFA
- ✅ Logs high-severity audit event
- ✅ Enforces retention policy check

### Inheritance

All paths under `/healthcare` inherit the compliance tag:
- `/healthcare/patients/P123.json` ✅ Protected
- `/healthcare/labs/results.json` ✅ Protected
- `/healthcare/billing/invoice.json` ✅ Protected

---

## Scenario 2: Key Compliance (GDPR/PII)

### Problem
You need to store Personally Identifiable Information (PII) and comply with GDPR (consent, right to erasure, encryption).

### Solution
Tag specific keys with GDPR compliance requirements.

### Example

```go
// 1. Tag the key
userKeyTag := &velocity.ComplianceTag{
    Path:          "/users/email/john.doe@example.com",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:     velocity.DataClassConfidential, // PII is confidential
    RetentionDays: 365,                             // 1 year retention
    EncryptionReq: true,
    AuditLevel:    "high",
    Owner:         "privacy-team",
}
ctm.TagPath(ctx, userKeyTag)

// 2. Prepare user data
userData := map[string]interface{}{
    "email":      "john.doe@example.com",
    "full_name":  "John Doe",
    "phone":      "+1-555-0123",
    "address":    "123 Main St, City, State",
    "ip_address": "192.168.1.100",
}
userJSON, _ := json.Marshal(userData)
```

### STORE Operation

```go
// Without encryption - FAILS for confidential data
writeReq := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john.doe@example.com",
    Operation: "write",
    Actor:     "app-backend",
    Encrypted: false, // ❌ Not encrypted
}
result, _ := ctm.ValidateOperation(ctx, writeReq)
// result.Allowed = false
// result.ViolatedRules = ["GDPR Article 32: confidential data must be encrypted"]

// With encryption - SUCCEEDS
writeReq.Encrypted = true
result, _ = ctm.ValidateOperation(ctx, writeReq)
// result.Allowed = true
// result.RequiredActions = ["verify consent for personal data processing"]

if result.Allowed {
    db.Set([]byte(writeReq.Path), userJSON)
}
```

**What Happens:**
- ✅ Enforces encryption for confidential PII
- ✅ Requires consent verification
- ✅ High-severity audit logging
- ✅ Blocks non-compliant operations

### GET Operation

```go
readReq := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john.doe@example.com",
    Operation: "read",
    Actor:     "app-backend",
}
result, _ := ctm.ValidateOperation(ctx, readReq)
// result.Allowed = true
// result.RequiredActions = [
//     "verify consent for personal data processing",
//     "log audit event with high severity"
// ]

if result.Allowed {
    data, _ := db.Get([]byte(readReq.Path))
}
```

**What Happens:**
- ✅ Checks consent requirement
- ✅ Audit logging
- ✅ Validates retention period

### DELETE (Right to Erasure)

```go
// GDPR Article 17: Right to Erasure
deleteReq := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john.doe@example.com",
    Operation: "delete",
    Actor:     "user-self",
    Reason:    "User exercised GDPR Article 17 right to erasure",
}
result, _ := ctm.ValidateOperation(ctx, deleteReq)
// result.Allowed = true
// result.RequiredActions = ["record deletion reason for GDPR compliance"]

if result.Allowed {
    db.Delete([]byte(deleteReq.Path))
}
```

**What Happens:**
- ✅ Supports right to erasure (GDPR Article 17)
- ✅ Requires deletion reason for compliance
- ✅ Audit trail maintained
- ✅ Validates retention period hasn't been exceeded

---

## Scenario 3: File Compliance (PCI DSS)

### Problem
You need to store payment card data and comply with PCI DSS requirements.

### Solution
Tag file storage paths with PCI DSS compliance requirements.

### Example

```go
// 1. Tag the file path
paymentFileTag := &velocity.ComplianceTag{
    Path:          "/files/payments",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    DataClass:     velocity.DataClassRestricted, // Cardholder data
    RetentionDays: 90,                            // PCI DSS requirement
    EncryptionReq: true,
    MFARequired:   true,
    AuditLevel:    "high",
    AccessPolicy:  "pci-dss-level-1",
}
ctm.TagPath(ctx, paymentFileTag)

// 2. Prepare payment data
paymentData := map[string]interface{}{
    "transaction_id": "TXN-2026-001",
    "card_number":    "4532-****-****-1234", // Masked
    "amount":         99.99,
    "timestamp":      "2026-01-24T10:30:00Z",
}
paymentJSON, _ := json.Marshal(paymentData)
```

### UPLOAD Operation

```go
writeReq := &velocity.ComplianceOperationRequest{
    Path:        "/files/payments/txn-001.json",
    Operation:   "write",
    Actor:       "payment-processor",
    Encrypted:   true,
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, writeReq)
// result.Allowed = true
// result.RequiredActions = [
//     "verify RBAC policy: pci-dss-level-1",
//     "log audit event with high severity"
// ]

if result.Allowed {
    db.UploadObject(ctx, writeReq.Path, paymentJSON)
}
```

**What Happens:**
- ✅ Enforces strong encryption (PCI DSS Requirement 3.4)
- ✅ Requires MFA for cardholder data access
- ✅ Validates access policy (RBAC integration)
- ✅ High-severity audit logging

### DOWNLOAD Operation

```go
readReq := &velocity.ComplianceOperationRequest{
    Path:        "/files/payments/txn-001.json",
    Operation:   "read",
    Actor:       "auditor",
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, readReq)

if result.Allowed {
    data, _, _ := db.GetObject(ctx, readReq.Path)
}
```

**What Happens:**
- ✅ Validates MFA requirement
- ✅ Checks access policy
- ✅ Audit logging

### DELETE Operation

```go
// Retention period check
deleteReq := &velocity.ComplianceOperationRequest{
    Path:        "/files/payments/txn-001.json",
    Operation:   "delete",
    Actor:       "system-cleanup",
    DataAge:     95,  // 95 days old (exceeds 90-day retention)
    MFAVerified: true,
    Reason:      "Automated deletion after retention period",
}
result, _ := ctm.ValidateOperation(ctx, deleteReq)

if result.Allowed {
    db.DeleteObject(ctx, deleteReq.Path)
}
```

**What Happens:**
- ✅ Validates retention period (PCI DSS Requirement 3.1)
- ✅ Requires deletion reason
- ✅ Audit trail
- ✅ Prevents premature deletion

---

## Compliance Frameworks

### HIPAA (Health Insurance Portability and Accountability Act)
**Use For:** Protected Health Information (PHI), medical records, patient data

**Key Requirements:**
- **Encryption:** PHI must be encrypted at rest and in transit
- **MFA:** Multi-factor authentication required
- **Minimum Necessary:** Access limited to minimum necessary data
- **Audit Logging:** All access must be logged
- **Retention:** 7 years (2555 days) minimum

**Validated Rules:**
- HIPAA Security Rule (encryption)
- HIPAA Privacy Rule (minimum necessary access)
- Breach notification requirements

**Example:**
```go
tag := &velocity.ComplianceTag{
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted,
    RetentionDays: 2555,  // 7 years
    EncryptionReq: true,
    MFARequired:   true,
}
```

---

### GDPR (General Data Protection Regulation)
**Use For:** EU citizen personal data, PII, user profiles

**Key Requirements:**
- **Consent:** Must verify consent for processing
- **Encryption:** Confidential PII must be encrypted
- **Right to Erasure:** Support deletion on request (Article 17)
- **Retention Limits:** Delete data after retention period
- **Deletion Reason:** Record reason for deletions

**Validated Rules:**
- GDPR Article 5(1)(e): Storage limitation
- GDPR Article 17: Right to erasure
- GDPR Article 32: Security of processing

**Example:**
```go
tag := &velocity.ComplianceTag{
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:     velocity.DataClassConfidential,
    RetentionDays: 365,
    EncryptionReq: true,
}
```

---

### PCI DSS (Payment Card Industry Data Security Standard)
**Use For:** Credit card data, payment information, cardholder data

**Key Requirements:**
- **Strong Encryption:** Cardholder data must use strong encryption
- **MFA:** Multi-factor authentication required
- **Access Control:** Role-based access policies
- **Retention:** 90 days maximum for transaction data
- **Audit Logging:** All access must be logged

**Validated Rules:**
- PCI DSS Requirement 3.1: Retention policy
- PCI DSS Requirement 3.4: Encryption
- PCI DSS Requirement 8: Access control

**Example:**
```go
tag := &velocity.ComplianceTag{
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    DataClass:     velocity.DataClassRestricted,
    RetentionDays: 90,
    EncryptionReq: true,
    MFARequired:   true,
    AccessPolicy:  "pci-dss-level-1",
}
```

---

### SOC 2 (Service Organization Control 2)
**Use For:** Cloud services, SaaS platforms, service providers

**Key Requirements:**
- **Access Control:** Strong access policies
- **Audit Logging:** Comprehensive audit trails
- **Encryption:** Protect sensitive data
- **Change Management:** Track all changes

**Example:**
```go
tag := &velocity.ComplianceTag{
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkSOC2},
    DataClass:     velocity.DataClassConfidential,
    AuditLevel:    "high",
    AccessPolicy:  "soc2-access-policy",
}
```

---

### FIPS (Federal Information Processing Standards)
**Use For:** Government data, federal systems

**Key Requirements:**
- **Approved Algorithms:** AES-256, SHA-256/384/512
- **Key Management:** Approved key management practices
- **Compliance Level:** FIPS 140-2 Level 2 or higher

**Validated Rules:**
- FIPS 140-2: Approved cryptographic algorithms
- FIPS 140-2 Level 2: Key management

**Example:**
```go
req := &velocity.ComplianceOperationRequest{
    CryptoAlgorithm: "AES-256-GCM", // Approved algorithm
}
```

---

## Data Classifications

### DataClassPublic
- No restrictions
- Publicly available information
- No encryption required

### DataClassInternal
- Internal use only
- Low sensitivity
- Basic access controls

### DataClassConfidential
- **Sensitive business data, PII**
- Encryption recommended
- Access controls required
- Audit logging

### DataClassRestricted
- **Highly sensitive: PHI, cardholder data, SSN**
- Encryption mandatory
- MFA required
- High-level audit logging
- Strict access controls

---

## Validation Flow

### How It Works

```
1. Tag Path with Compliance Requirements
   ↓
2. Attempt Operation (store/get/update/delete)
   ↓
3. Call ValidateOperation()
   ↓
4. Check Compliance Rules
   • Encryption required?
   • MFA verified?
   • Retention period?
   • Access policy?
   ↓
5. Return ValidationResult
   • Allowed: true/false
   • ViolatedRules: []string
   • RequiredActions: []string
   ↓
6. Execute Operation (if Allowed=true)
   ↓
7. Implement Required Actions
   • Log audit event
   • Verify consent
   • Check RBAC policy
```

### Validation Result Structure

```go
type ComplianceValidationResult struct {
    Allowed         bool              // Can the operation proceed?
    Reason          string            // Why it was allowed/denied
    AppliedTag      *ComplianceTag    // The tag that was applied
    ViolatedRules   []string          // List of compliance violations
    RequiredActions []string          // Actions you must implement
}
```

### Example Response

```go
result := &ComplianceValidationResult{
    Allowed: false,
    ViolatedRules: [
        "HIPAA Security Rule: PHI must be encrypted",
        "MFA verification required for PHI access",
    ],
    RequiredActions: [
        "encrypt data before write",
        "verify MFA for PHI access",
        "log audit event with high severity",
    ],
}
```

---

## API Reference

### Tag Management

#### TagPath
```go
func (ctm *ComplianceTagManager) TagPath(ctx context.Context, tag *ComplianceTag) error
```
Apply a compliance tag to a path.

#### GetTag
```go
func (ctm *ComplianceTagManager) GetTag(path string) *ComplianceTag
```
Get the merged compliance tag for a path (includes inheritance).

#### GetTags
```go
func (ctm *ComplianceTagManager) GetTags(path string) []*ComplianceTag
```
Get all individual tags for a path.

#### RemoveTag
```go
func (ctm *ComplianceTagManager) RemoveTag(ctx context.Context, path string) error
```
Remove all compliance tags from a path.

#### RemoveTagByID
```go
func (ctm *ComplianceTagManager) RemoveTagByID(ctx context.Context, tagID string) error
```
Remove a specific tag by its ID.

### Tag Updates

#### UpdateTag
```go
func (ctm *ComplianceTagManager) UpdateTag(
    ctx context.Context,
    tagID string,
    updateFn func(*ComplianceTag) error,
) error
```
Update a specific tag by its unique ID.

#### UpdateTagByPathAndFramework
```go
func (ctm *ComplianceTagManager) UpdateTagByPathAndFramework(
    ctx context.Context,
    path string,
    framework ComplianceFramework,
    updateFn func(*ComplianceTag) error,
) error
```
Update the first tag matching a specific framework for a path.

#### UpdateAllTagsForPath
```go
func (ctm *ComplianceTagManager) UpdateAllTagsForPath(
    ctx context.Context,
    path string,
    updateFn func(*ComplianceTag) error,
) error
```
Update all tags for a path.

### Validation

#### ValidateOperation
```go
func (ctm *ComplianceTagManager) ValidateOperation(
    ctx context.Context,
    req *ComplianceOperationRequest,
) (*ComplianceValidationResult, error)
```
Validate an operation against compliance requirements.

### Queries

#### ListTagsByFramework
```go
func (ctm *ComplianceTagManager) ListTagsByFramework(
    framework ComplianceFramework,
) []*ComplianceTag
```
Get all tags using a specific framework.

#### GetAllTags
```go
func (ctm *ComplianceTagManager) GetAllTags() map[string][]*ComplianceTag
```
Get all compliance tags.

---

## Best Practices

### 1. Tag at the Folder Level
For organizational data, tag folders rather than individual files:
```go
// Good
ctm.TagPath(ctx, &ComplianceTag{Path: "/healthcare"})

// Less efficient
ctm.TagPath(ctx, &ComplianceTag{Path: "/healthcare/patient1.json"})
ctm.TagPath(ctx, &ComplianceTag{Path: "/healthcare/patient2.json"})
```

### 2. Always Validate Before Operations
```go
// Always validate first
result, _ := ctm.ValidateOperation(ctx, req)
if !result.Allowed {
    log.Printf("Operation denied: %v", result.ViolatedRules)
    return errors.New("compliance violation")
}

// Then execute
db.Set(key, value)
```

### 3. Implement Required Actions
The validation returns actions you **must** implement:
```go
for _, action := range result.RequiredActions {
    switch {
    case strings.Contains(action, "audit"):
        auditLogger.Log(req.Actor, req.Operation, req.Path)
    case strings.Contains(action, "consent"):
        consentManager.Verify(req.Actor, req.Path)
    case strings.Contains(action, "RBAC"):
        rbac.CheckPolicy(req.Actor, tag.AccessPolicy)
    }
}
```

### 4. Use Multiple Frameworks
Apply multiple compliance frameworks to the same data:
```go
tag := &velocity.ComplianceTag{
    Path: "/sensitive-data",
    Frameworks: []velocity.ComplianceFramework{
        velocity.FrameworkGDPR,
        velocity.FrameworkSOC2,
        velocity.FrameworkHIPAA,
    },
}
```
Validation checks **all** frameworks.

### 5. Set Appropriate Data Classifications
Match classification to data sensitivity:
- **Public:** Marketing materials, public documentation
- **Internal:** Internal memos, non-sensitive business data
- **Confidential:** PII, business secrets, user data
- **Restricted:** PHI, payment card data, SSN

### 6. Handle Retention Properly
Check data age and enforce retention:
```go
req.DataAge = calculateAge(createdAt)
result, _ := ctm.ValidateOperation(ctx, req)

if containsRetentionViolation(result.ViolatedRules) {
    // Data exceeds retention - must delete
    db.Delete(key)
}
```

---

## Complete Working Example

See [compliance_full_demo.go](./compliance_full_demo.go) for a complete demonstration showing:
- ✅ Folder tagging with HIPAA
- ✅ Key tagging with GDPR
- ✅ File tagging with PCI DSS
- ✅ All operations (store, get, update, delete)
- ✅ Validation outcomes
- ✅ Inheritance
- ✅ Error handling

Run it:
```bash
cd examples
go run compliance_full_demo.go
```

---

## Troubleshooting

### Operation Denied - Why?

**Check ViolatedRules:**
```go
if !result.Allowed {
    for _, rule := range result.ViolatedRules {
        fmt.Println(rule)
        // "HIPAA Security Rule: PHI must be encrypted"
    }
}
```

### Common Issues

1. **"encryption required but data is not encrypted"**
   - Solution: Set `req.Encrypted = true`

2. **"MFA verification required"**
   - Solution: Set `req.MFAVerified = true`

3. **"data exceeds retention period"**
   - Solution: Delete or anonymize expired data

4. **"confidential data must be encrypted"**
   - Solution: Encrypt confidential/restricted data

---

## Summary

| Aspect | Folder Tags | Key Tags | File Tags |
|--------|------------|----------|-----------|
| **Applies To** | All paths under folder | Specific key-value | File storage paths |
| **Inheritance** | ✅ Yes | ❌ No | ✅ Yes |
| **Use Case** | Organizational data | Individual records | Object storage |
| **Examples** | `/healthcare`, `/finance` | `/users/email/john@ex.com` | `/files/payments` |

**What Happens During Operations:**
1. **Validation** occurs BEFORE execution
2. **Allowed=false** blocks the operation
3. **ViolatedRules** explains why it was blocked
4. **RequiredActions** tells you what to implement
5. **Audit logging** is tracked via RequiredActions

**Key Insight:** Compliance tagging is **proactive** - it prevents non-compliant operations from happening, rather than detecting violations after the fact.

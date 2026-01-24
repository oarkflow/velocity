# Compliance Tagging Quick Reference

## What is Compliance Tagging?

Compliance tagging allows you to apply regulatory requirements (HIPAA, GDPR, PCI DSS, etc.) to your data and **validate every operation** (store, get, update, delete) **before** it executes. If an operation violates compliance rules, it's **blocked** with specific violation reasons.

---

## Can I Tag...?

### ✅ YES - You Can Tag:

| What | Example Path | Use For |
|------|-------------|---------|
| **Folders** | `/healthcare` | Apply to ALL data under that path (PHI, medical records) |
| **Keys** | `/users/email/john@ex.com` | Specific key-value pairs (user profiles, PII) |
| **Files** | `/files/payments` | File storage paths (payment files, documents) |

---

## What Happens During Operations?

### Before Any Operation:

```go
// 1. Tag the path
tag := &velocity.ComplianceTag{
    Path:          "/healthcare/patients",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    EncryptionReq: true,
}
ctm.TagPath(ctx, tag)

// 2. Validate BEFORE executing
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "write",
    Encrypted: false, // ❌ Not encrypted
}
result, _ := ctm.ValidateOperation(ctx, req)

// 3. Check if allowed
if !result.Allowed {
    // Operation BLOCKED ❌
    fmt.Println("Violations:", result.ViolatedRules)
    // ["HIPAA Security Rule: PHI must be encrypted"]
    return
}

// 4. Execute only if allowed
db.Put(key, value)
```

### The Flow:

```
Tag Path → Attempt Operation → Validate → Check Result → Execute (if allowed)
```

---

## Scenario 1: Folder with HIPAA (PHI Data)

### Setup

```go
// Tag the /healthcare folder
healthcareTag := &velocity.ComplianceTag{
    Path:          "/healthcare",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted, // PHI
    RetentionDays: 2555,                          // 7 years
    EncryptionReq: true,
}
ctm.TagPath(ctx, healthcareTag)
```

### What Happens: STORE

```go
// ❌ WITHOUT encryption
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "write",
    Encrypted: false,
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.Allowed = false
// result.ViolatedRules = ["HIPAA Security Rule: PHI must be encrypted"]

// ✅ WITH encryption
req.Encrypted = true
result, _ = ctm.ValidateOperation(ctx, req)
// result.Allowed = true
if result.Allowed {
    db.Put([]byte(req.Path), data)
}
```

**Result:**
- ❌ **Blocked** if not encrypted
- ✅ **Allowed** if encrypted
- 📋 **Required Actions:** audit logging, BAA verification

### What Happens: GET

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "read",
    Actor:     "doctor-smith",
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.Allowed = true
// result.RequiredActions = ["enforce minimum necessary access for PHI", ...]

if result.Allowed {
    data, _ := db.Get([]byte(req.Path))
}
```

**Result:**
- ✅ **Allowed** (with requirements)
- 📋 **Required Actions:** minimum necessary access, audit logging

### What Happens: UPDATE

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "write",
    Encrypted: true,
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    db.Put([]byte(req.Path), updatedData)
}
```

**Result:**
- ✅ Same validation as STORE
- 📋 Ensures encrypted updates

### What Happens: DELETE

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "delete",
    Reason:    "Patient requested data deletion",
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    db.Delete([]byte(req.Path))
}
```

**Result:**
- ⚠️ **Warning** if no deletion reason
- ✅ **Allowed** (requires audit logging)
- 📋 **Required Actions:** log deletion reason

### Inheritance

```
/healthcare (tagged) ← Applies to ALL children
├── /healthcare/patients/P123.json ✅ Protected
├── /healthcare/labs/results.json ✅ Protected
└── /healthcare/billing/invoice.json ✅ Protected
```

---

## Scenario 2: Key with GDPR (PII Data)

### Setup

```go
// Tag specific key
userTag := &velocity.ComplianceTag{
    Path:          "/users/email/john@example.com",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:     velocity.DataClassConfidential, // PII
    RetentionDays: 365,
    EncryptionReq: true,
}
ctm.TagPath(ctx, userTag)
```

### What Happens: STORE

```go
// ❌ WITHOUT encryption (confidential data)
req := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john@example.com",
    Operation: "write",
    Encrypted: false,
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.Allowed = false
// result.ViolatedRules = ["GDPR Article 32: confidential data must be encrypted"]

// ✅ WITH encryption
req.Encrypted = true
result, _ = ctm.ValidateOperation(ctx, req)
// result.Allowed = true
// result.RequiredActions = ["verify consent for personal data processing"]

if result.Allowed {
    db.Put([]byte(req.Path), userData)
}
```

**Result:**
- ❌ **Blocked** if not encrypted
- ✅ **Allowed** if encrypted
- 📋 **Required Actions:** verify consent, audit logging

### What Happens: GET

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john@example.com",
    Operation: "read",
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.RequiredActions = ["verify consent for personal data processing"]

if result.Allowed {
    data, _ := db.Get([]byte(req.Path))
}
```

**Result:**
- ✅ **Allowed**
- 📋 **Required Actions:** verify consent, audit logging

### What Happens: DELETE (Right to Erasure)

```go
// GDPR Article 17: Right to be forgotten
req := &velocity.ComplianceOperationRequest{
    Path:      "/users/email/john@example.com",
    Operation: "delete",
    Reason:    "User exercised GDPR Article 17 right to erasure",
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    db.Delete([]byte(req.Path))
}
```

**Result:**
- ✅ **Allowed**
- 📋 **Required Actions:** record deletion reason

---

## Scenario 3: File with PCI DSS (Credit Card Data)

### Setup

```go
// Tag file storage path
paymentTag := &velocity.ComplianceTag{
    Path:          "/files/payments",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    DataClass:     velocity.DataClassRestricted, // Cardholder data
    RetentionDays: 90,                            // PCI DSS requirement
    EncryptionReq: true,
    AccessPolicy:  "pci-dss-level-1",
}
ctm.TagPath(ctx, paymentTag)
```

### What Happens: UPLOAD

```go
req := &velocity.ComplianceOperationRequest{
    Path:        "/files/payments/txn-001.json",
    Operation:   "write",
    Encrypted:   true,
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.Allowed = true
// result.RequiredActions = [
//     "PCI DSS 10.1: log all access to cardholder data",
//     "verify RBAC policy: pci-dss-level-1"
// ]

if result.Allowed {
    db.Put([]byte(req.Path), paymentData)
}
```

**Result:**
- ✅ **Allowed** (with encryption)
- 📋 **Required Actions:** PCI DSS audit logging, RBAC verification

### What Happens: DOWNLOAD

```go
req := &velocity.ComplianceOperationRequest{
    Path:        "/files/payments/txn-001.json",
    Operation:   "read",
    MFAVerified: true,
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    data, _ := db.Get([]byte(req.Path))
}
```

**Result:**
- ✅ **Allowed**
- 📋 **Required Actions:** audit logging, RBAC

### What Happens: DELETE (Retention Check)

```go
req := &velocity.ComplianceOperationRequest{
    Path:      "/files/payments/txn-001.json",
    Operation: "delete",
    DataAge:   95, // Exceeds 90-day retention
    Reason:    "Automated deletion after retention period",
}
result, _ := ctm.ValidateOperation(ctx, req)
if result.Allowed {
    db.Delete([]byte(req.Path))
}
```

**Result:**
- ✅ **Allowed** (retention exceeded)
- 📋 **Required Actions:** audit logging

---

## Validation Result Structure

```go
type ComplianceValidationResult struct {
    Allowed         bool           // Can operation proceed?
    Reason          string         // Why allowed/denied
    ViolatedRules   []string       // Compliance violations
    RequiredActions []string       // Actions you must implement
}
```

### Example: Blocked Operation

```go
result := &ComplianceValidationResult{
    Allowed: false,
    ViolatedRules: [
        "HIPAA Security Rule: PHI must be encrypted",
        "encryption required but data is not encrypted",
    ],
    RequiredActions: [
        "encrypt data before write",
        "log audit event with high severity",
    ],
}
```

---

## Compliance Frameworks

| Framework | Use For | Key Requirements |
|-----------|---------|------------------|
| **HIPAA** | Healthcare data (PHI) | Encryption, MFA, 7-year retention |
| **GDPR** | EU citizen data (PII) | Consent, encryption, right to erasure |
| **PCI DSS** | Payment card data | Strong encryption, MFA, 90-day retention |
| **SOC 2** | Cloud services | Access control, audit trails |
| **FIPS** | Government data | Approved algorithms (AES-256, SHA-256) |

---

## Data Classifications

| Level | Examples | Requirements |
|-------|----------|--------------|
| **Public** | Marketing materials | None |
| **Internal** | Internal memos | Basic access control |
| **Confidential** | PII, business secrets | Encryption recommended |
| **Restricted** | PHI, SSN, payment cards | Encryption mandatory, MFA required |

---

## Key Takeaways

### ✅ What Happens:

1. **Validation occurs BEFORE execution**
2. **Allowed=false BLOCKS the operation**
3. **ViolatedRules explains WHY it was blocked**
4. **RequiredActions tells you WHAT to implement**
5. **Inheritance: child paths inherit parent tags**

### ✅ Benefits:

- **Proactive:** Prevents violations before they happen
- **Automatic:** Validates every operation
- **Specific:** Tells you exactly what's wrong
- **Flexible:** Apply multiple frameworks to same data
- **Inherited:** Tag folders to protect all children

### ✅ You MUST:

1. **Call ValidateOperation() before every operation**
2. **Check result.Allowed before executing**
3. **Implement RequiredActions** (audit logging, consent verification, etc.)
4. **Handle violations** (log, alert, block)

---

## Complete Example

See [compliance_full_demo.go](./examples/compliance_full_demo.go) for a complete working example.

Run it:
```bash
cd examples
go run compliance_full_demo.go
```

---

## Quick API Reference

```go
// Tag a path
ctm.TagPath(ctx, &velocity.ComplianceTag{...})

// Validate operation
result, _ := ctm.ValidateOperation(ctx, &velocity.ComplianceOperationRequest{...})

// Check if allowed
if result.Allowed {
    // Execute operation
}

// Handle violations
for _, rule := range result.ViolatedRules {
    log.Error(rule)
}

// Implement required actions
for _, action := range result.RequiredActions {
    // Audit log, verify consent, check RBAC, etc.
}
```

---

## Summary Table

| Scenario | Tag Level | What's Protected | Operations Validated | Key Enforcement |
|----------|-----------|------------------|----------------------|-----------------|
| **Folder (HIPAA)** | `/healthcare` | ALL child paths | Store, Get, Update, Delete | Encryption, Audit logging |
| **Key (GDPR)** | `/users/email/john@ex.com` | Specific key-value | Store, Get, Update, Delete | Encryption, Consent, Right to erasure |
| **File (PCI DSS)** | `/files/payments` | File storage paths | Upload, Download, Delete | Encryption, RBAC, Retention |

**Bottom Line:** Compliance tagging is **proactive** - it prevents non-compliant operations from happening, rather than detecting violations after the fact. Every operation is validated against compliance rules **before** execution, and blocked operations receive specific violation reasons and required remediation actions.

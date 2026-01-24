# Compliance Tagging Examples

This directory contains comprehensive examples demonstrating Velocity's compliance tagging system.

## Available Examples

### 1. **compliance_full_demo.go** - Complete Demonstration
A comprehensive example showing all three scenarios:
- ✅ Folder tagging with HIPAA (PHI/healthcare data)
- ✅ Key tagging with GDPR (PII/user data)
- ✅ File tagging with PCI DSS (credit card data)
- ✅ All operations: STORE, GET, UPDATE, DELETE
- ✅ Validation results and enforcement

**Run it:**
```bash
go run compliance_full_demo.go
```

**What you'll see:**
- How to tag paths with compliance requirements
- What happens when operations violate compliance rules (blocked with reasons)
- What happens when operations comply (allowed with required actions)
- How inheritance works (child paths inherit parent tags)

---

### 2. **multiple_tags_demo.go** - Multiple Compliance Tags
Shows how to apply multiple compliance frameworks to the same data:
- Multiple tags on same path (GDPR + SOC2)
- Tag merging with most restrictive settings
- Framework filtering
- Inheritance with multiple tags

**Run it:**
```bash
go run multiple_tags_demo.go
```

---

### 3. **tag_update_demo.go** - Tag Management
Demonstrates the three update methods for managing tags:
- UpdateTag(tagID, fn) - Update specific tag by ID
- UpdateTagByPathAndFramework(path, framework, fn) - Update by framework
- UpdateAllTagsForPath(path, fn) - Bulk update
- RemoveTagByID(tagID) - Remove specific tag

**Run it:**
```bash
go run tag_update_demo.go
```

---

## Key Concepts Demonstrated

### Folder Tagging (HIPAA/PHI)
```go
// Tag applies to ALL paths under /healthcare
healthcareTag := &velocity.ComplianceTag{
    Path:          "/healthcare",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
    DataClass:     velocity.DataClassRestricted,
    EncryptionReq: true,
}
```

**Inheritance:**
- `/healthcare/patients/P123.json` ✅ Protected
- `/healthcare/labs/results.json` ✅ Protected

### Key Tagging (GDPR/PII)
```go
// Tag specific key-value pair
userTag := &velocity.ComplianceTag{
    Path:       "/users/email/john@example.com",
    Frameworks: []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    DataClass:  velocity.DataClassConfidential,
}
```

### File Tagging (PCI DSS/Credit Cards)
```go
// Tag file storage path
paymentTag := &velocity.ComplianceTag{
    Path:         "/files/payments",
    Frameworks:   []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
    DataClass:    velocity.DataClassRestricted,
    AccessPolicy: "pci-dss-level-1",
}
```

---

## Validation Examples

### Store Operation (Blocked)
```go
// ❌ WITHOUT encryption - BLOCKED
req := &velocity.ComplianceOperationRequest{
    Path:      "/healthcare/patients/P123.json",
    Operation: "write",
    Encrypted: false,
}
result, _ := ctm.ValidateOperation(ctx, req)
// result.Allowed = false
// result.ViolatedRules = ["HIPAA Security Rule: PHI must be encrypted"]
```

### Store Operation (Allowed)
```go
// ✅ WITH encryption - ALLOWED
req.Encrypted = true
result, _ = ctm.ValidateOperation(ctx, req)
// result.Allowed = true
// result.RequiredActions = ["log audit event with high severity"]

if result.Allowed {
    db.Put([]byte(req.Path), data)
}
```

---

## What Each Example Shows

| Example | Demonstrates |
|---------|-------------|
| **compliance_full_demo.go** | Complete workflow: tag → validate → execute |
| **multiple_tags_demo.go** | Multiple frameworks on same path |
| **tag_update_demo.go** | Managing and updating tags |

---

## Documentation

For complete documentation, see:
- **[COMPLIANCE_GUIDE.md](../COMPLIANCE_GUIDE.md)** - Comprehensive guide with all frameworks
- **[COMPLIANCE_QUICK_REFERENCE.md](../COMPLIANCE_QUICK_REFERENCE.md)** - Quick reference for common scenarios

---

## Quick Start

1. **Tag a path:**
```go
ctm := velocity.NewComplianceTagManager(db)
ctm.TagPath(ctx, &velocity.ComplianceTag{
    Path:          "/sensitive-data",
    Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
    EncryptionReq: true,
})
```

2. **Validate before operation:**
```go
result, _ := ctm.ValidateOperation(ctx, &velocity.ComplianceOperationRequest{
    Path:      "/sensitive-data/user.json",
    Operation: "write",
    Encrypted: true,
})
```

3. **Execute if allowed:**
```go
if result.Allowed {
    db.Put(key, value)
} else {
    log.Error("Compliance violation:", result.ViolatedRules)
}
```

---

## Supported Compliance Frameworks

- ✅ **HIPAA** - Healthcare data (PHI)
- ✅ **GDPR** - EU citizen data (PII)
- ✅ **PCI DSS** - Payment card data
- ✅ **SOC 2** - Cloud services
- ✅ **NIST** - Government standards
- ✅ **FIPS** - Federal information processing

---

## Output Example

When you run `compliance_full_demo.go`, you'll see:

```
═══════════════════════════════════════════════════════════════════════
SCENARIO 1: Folder Tagged with HIPAA Compliance (PHI Data)
═══════════════════════════════════════════════════════════════════════

✓ Tagged /healthcare folder with HIPAA compliance
  - Frameworks: [HIPAA]
  - Data Classification: restricted (PHI)
  - Encryption Required: true
  - Retention: 2555 days (7 years)

📋 Attempting to STORE patient data (PHI)...

❌ VALIDATION RESULT (without encryption):
   Allowed: false
   ⚠️  VIOLATION: HIPAA Security Rule: PHI must be encrypted

📋 Attempting to STORE with ENCRYPTION...
✅ VALIDATION RESULT: Allowed=true
   ✓ Patient data stored successfully with encryption
```

---

## Next Steps

1. Run the examples to see compliance validation in action
2. Read [COMPLIANCE_GUIDE.md](../COMPLIANCE_GUIDE.md) for detailed framework documentation
3. Check [COMPLIANCE_QUICK_REFERENCE.md](../COMPLIANCE_QUICK_REFERENCE.md) for quick API reference
4. Implement compliance tagging in your application

---

## Questions?

The examples are self-contained and well-commented. Read through the code to understand:
- How to structure compliance tags
- How validation works
- What gets blocked and why
- What actions are required
- How inheritance works

Happy coding! 🚀

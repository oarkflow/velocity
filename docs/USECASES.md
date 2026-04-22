# Secretr Business Use Cases & Workflows

This document outlines how different sectors and institutions can leverage Secretr's "Military-grade" capabilities to solve real-world security challenges.

---

## 1. Healthcare: HIPAA-Compliant Patient Data Sharing
**Objective**: Securely share sensitive patient records with external specialists while maintaining a strict audit trail and preventing unauthorized redistribution.

### Workflow:
1. **Initialize Audit for Compliance**:
   ```bash
   secretr audit verify
   ```
2. **Upload Encrypted Record**:
   ```bash
   secretr file upload --name "patient-001-labs" --path "./records/labs.pdf"
   ```
3. **Apply MFA & Download Limits**:
   ```bash
   secretr file protect --name "patient-001-labs" --require-mfa --max-downloads 1
   ```
4. **Grant Access to Specialist**:
   ```bash
   secretr access grant --grantee "doc-smith-id" --resource "patient-001-labs" --type file --expires-in 24h
   ```

> [!TIP]
> **Executable Demo**: [healthcare_hipaa.sh](scripts/usecases/healthcare_hipaa.sh)

---

## 2. Finance: High-Integrity Financial Ledger Audit
**Objective**: Ensure that financial configuration secrets and transaction logs are tamper-proof and verifiable for SEC/FINRA audits.

### Workflow:
1. **Create Immutable Banking Secret**:
   ```bash
   secretr secret create --name "fin/swift/api-key" --value "sk_live_..." --immutable
   ```
2. **Periodic Integrity Verification**:
   ```bash
   secretr audit verify
   ```
3. **Export Signed Evidence**:
   ```bash
   secretr audit export --output "q4-audit-evidence.json"
   ```

> [!TIP]
> **Executable Demo**: [finance_audit.sh](scripts/usecases/finance_audit.sh)

---

## 3. Defense & National Security: Targeted Field Intelligence
**Objective**: Distribute field manuals to personnel in specific regions and revoke them instantly if a device is compromised or the theater of operations changes.

### Workflow:
1. **Upload Classified Asset**:
   ```bash
   secretr file upload --name "op-blue-manual" --path "./field/manual.pdf"
   ```
2. **Apply Geofence & Remote Kill**:
   ```bash
   secretr file protect --name "op-blue-manual" --geofence "US,GB" --remote-kill
   ```
3. **Emergency Revocation**:
   ```bash
   secretr file kill --name "op-blue-manual" --reason "Personnel MIA"
   ```

> [!TIP]
> **Executable Demo**: [defense_intel.sh](scripts/usecases/defense_intel.sh)

---

## 4. Software Engineering: Per-Build "Burn-after-read" Secrets
**Objective**: Inject dynamic secrets into a CI/CD pipeline that are valid only for the duration of the build and vanish immediately after.

### Workflow:
1. **Register Build Pipeline**:
   ```bash
   secretr cicd create-pipeline --name "frontend-prod" --provider github --repo "org/app"
   ```
2. **Create Temporary Deployment Key**:
   ```bash
   secretr secret create --name "svc/deploy-key" --value "..." --read-once
   ```

> [!TIP]
> **Executable Demo**: [devsecops_cicd.sh](scripts/usecases/devsecops_cicd.sh)

---

## 5. Legal & Corporate Governance: Legal Hold
**Objective**: During litigation, preserve all communications and documents across an entire organization, preventing any staff member (even admins) from deleting evidence.

### Workflow:
1. **Declare Security Incident**:
   ```bash
   secretr incident declare --type "Litigation" --severity "critical" --description "SEC Inquiry 2024"
   ```
2. **Enable Global Legal Hold**:
   ```bash
   secretr org legal-hold --enable
   ```

> [!TIP]
> **Executable Demo**: [legal_hold.sh](scripts/usecases/legal_hold.sh)

---

## 6. Remote Teams: Secure Time-Value Sharing
**Objective**: Share a sensitive configuration file with a freelancer that expires in 2 hours and can only be opened from their specific country.

### Workflow:
1. **Create Secure Share**:
   ```bash
   secretr share create --type file --resource "freelancer-config" --expires-in 2h --one-time
   ```
2. **Apply Geographic Restriction**:
   ```bash
   secretr file protect --name "freelancer-config" --geofence "DE"
   ```

> [!TIP]
> **Executable Demo**: [remote_share.sh](scripts/usecases/remote_share.sh)

---

## 7. Manufacturing: Intellectual Property (IP) Protection
**Objective**: Share sensitive proprietary design files with overseas manufacturers while retaining the ability to kill access if a contract is terminated.

### Workflow:
1. **Upload R&D Asset**:
   ```bash
   secretr file upload --name "design/motor-v4" --path "./designs/motor.dwg"
   ```
2. **Apply Multi-Layer Protection**:
   ```bash
   secretr file protect --name "design/motor-v4" --geofence "IN,CN" --remote-kill --max-downloads 5
   ```

> [!TIP]
> **Executable Demo**: [manufacturing_ip.sh](scripts/usecases/manufacturing_ip.sh)

---

## 8. Incident Response: Breach Containment
**Objective**: Respond to an active credential leak by freezing the organization and performing a global secret rotation.

### Workflow:
1. **Freeze Organization**:
   ```bash
   secretr incident freeze --org-id "my-org"
   ```
2. **Global Rotation**:
   ```bash
   secretr incident rotate --all
   ```

> [!TIP]
> **Executable Demo**: [incident_response.sh](scripts/usecases/incident_response.sh)

---

---

## 10. Policy & Access Control: Dynamic Governance
**Objective**: Dynamically manage permissions and policies for different teams and resources.

### Workflow:
1. **Create Policy**:
   ```bash
   secretr policy create --name "finance-admin"
   ```
2. **Grant Access**:
   ```bash
   secretr access grant --grantee "user-id" --resource "fin/*" --type secret --scopes "secret:*"
   ```

> [!TIP]
> **Executable Demo**: [acl_and_policy.sh](scripts/usecases/acl_and_policy.sh)

---

## 11. Monitoring & Alerting: Security Oversight
**Objective**: Monitor all security events and receive alerts for suspicious activities.

### Workflow:
1. **Query Events**:
   ```bash
   secretr monitoring events --limit 10
   ```
2. **List Alerts**:
   ```bash
   secretr alert list --status active
   ```

> [!TIP]
> **Executable Demo**: [monitoring_alerts.sh](scripts/usecases/monitoring_alerts.sh)

---

## 12. Library Usage: Go Integration
**Objective**: Use Secretr's core logic directly in your Go applications.

### Example:
```go
import (
    "github.com/oarkflow/velocity/pkg/secretr/core/secrets"
    "github.com/oarkflow/velocity/pkg/secretr/storage"
)

// ... see examples/library/main.go for full implementation
```

> [!TIP]
> **Executable Example**: [examples/library/main.go](examples/library/main.go)

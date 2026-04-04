# Compliance Mapping: FERPA, GDPR, HIPAA

Practical control mapping for production readiness and audit prep.

Legal interpretation and regulatory applicability must be reviewed and approved by qualified legal counsel before relying on this document for certification, attestation, or contractual commitments.

## FERPA

| Control requirement | Platform control(s) | Evidence source | Owner | Status |
|---|---|---|---|---|
| Access to student records is limited to authorized users with legitimate educational interest | RBAC scopes, deny-first authz, ACL checks on protected resources | `secretr audit verify`, authz deny/allow events, role/entitlement configuration export | Security + Identity Admin | Planned |
| Student record access and changes are auditable | Audit ledger integrity checks and command/API audit events | Audit logs, `secretr backup audit --verify-chain`, incident evidence exports | Security Operations | Planned |
| Student data at rest and in transit is protected | Encryption requirements via compliance tagging and secure transport defaults | Compliance tag configuration, validation results, platform encryption settings | Platform Engineering | Planned |
| Data retention/disposal follows institutional policy | Retention settings in compliance tags and controlled delete workflows | Compliance tag export, deletion audit events with actor/reason | Data Governance | Planned |

## GDPR

| Control requirement | Platform control(s) | Evidence source | Owner | Status |
|---|---|---|---|---|
| Personal data processing is access-controlled and least-privilege | RBAC + entitlements + ACL; org-scoped access boundaries | Authz logs, role/scope mapping, periodic access review records | Security + IAM | Planned |
| Personal data is protected by appropriate technical controls (Art. 32) | Encryption-required tagging for confidential/restricted data | Compliance validation logs, encryption configuration evidence | Platform Engineering | Planned |
| Processing activity and security events are traceable | Tamper-evident audit chain and monitoring event queries | `secretr audit verify`, `secretr monitoring events --limit 200` output | Security Operations | Planned |
| Backup/restore and incident response are tested and documented | Scheduled backup operations and incident drills | Backup drill records, incident timeline/export artifacts | SRE + Incident Commander | Planned |

## HIPAA

| Control requirement | Platform control(s) | Evidence source | Owner | Status |
|---|---|---|---|---|
| PHI access is restricted and enforceable | RBAC/entitlements/ACL on PHI-tagged resources | Access decision logs, entitlement policy snapshots, periodic review sign-off | Security + Compliance | Planned |
| PHI is encrypted and protected | HIPAA compliance tags with encryption requirement and secure key handling | Compliance validation results, key lifecycle evidence, config snapshots | Platform Engineering | Planned |
| Access and administrative actions are fully auditable | Audit chain verification and incident timeline/export commands | `secretr audit verify`, incident export package, audit retention records | Security Operations | Planned |
| Contingency operations (backup/restore) are validated | Backup create/verify/restore drills with RTO/RPO tracking | Drill runbooks, restore logs, signed drill reports | SRE | Planned |

## Governance Notes

- Status values should use: `Planned`, `In Progress`, `Implemented`, `Validated`.
- Keep evidence in immutable, access-controlled locations per `docs/SRE_SLO_AND_DRILLS.md` conventions.
- Revalidate this mapping at least quarterly and after major platform/authz changes.

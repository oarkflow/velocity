# External Security Assessment Policy

## Purpose

This policy defines mandatory external security assessments and release-gate requirements.

## Required Cadence

- Pre-GA: independent external audit and pentest are mandatory before first GA release.
- Ongoing: at least one external audit and one pentest every 12 months.
- Release-based: repeat assessment for every major release or architecture/security-significant change.

## Minimum Assessment Scope

Assessments must cover, at minimum:

- CLI attack surface (auth flows, local secret handling, command misuse paths)
- API attack surface (authn/authz, input validation, rate limiting, tenant isolation)
- Authorization model (RBAC/ABAC correctness, privilege escalation paths)
- Storage and data handling (object/metadata access controls, encryption, backup/restore paths)
- Key management (generation, storage, rotation, revocation, runtime injection)

Out-of-scope items must be explicitly documented and approved by Security Lead.

## Required Repository Evidence

The following artifacts are required in-repo for each assessment cycle:

- External report: full technical report with finding severities and affected components
- Remediation tracker: finding-by-finding status, owner, due date, and closure evidence
- Executive summary: business risk summary, residual risk statement, and release recommendation

Evidence location:

- `docs/PENTEST_REPORT.md` (or cycle-specific equivalent)
- `docs/THREAT_MODEL.md` residual risk and sign-off updated for current cycle

## Release Gate Conditions

- `Critical`: release blocked until fixed and externally or independently re-verified.
- `High`: release blocked until fixed, or formally accepted with compensating controls and explicit Security Lead + Product Owner sign-off.
- `Medium`: remediation plan required before release, with owner and due date; unresolved medium findings require risk acceptance.
- `Low`/`Info`: tracked in backlog; do not block release unless clustered to create material risk.

Gate enforcement requirements:

- No production release without current-cycle evidence artifacts committed.
- No release when sign-off tables are incomplete.
- Any exception must include documented expiry date and approving roles.

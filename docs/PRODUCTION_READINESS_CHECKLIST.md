# Production Readiness Checklist

Use this checklist before cutting or promoting a production release of Secretr/Velocity.

## Mandatory Governance Gates

- Compliance mapping gate: `docs/COMPLIANCE_MAPPING_FERPA_GDPR_HIPAA.md` must be current for in-scope release controls and ownership.
- SRE governance gate: `docs/SRE_SLO_AND_DRILLS.md` SLO targets, drill cadence, and evidence checklist must be satisfied for the release window.

## Build/Release Gates

- Build production binary without dev tag: `go build -o dist/secretr ./cmd/secretr`
- Run core test suite: `go test ./...`
- Confirm CI hardening workflow passes (`.github/workflows/secretr-hardening.yml`)
- Verify release artifact naming does not include dev/debug variants

## Security Controls

- Verify deny-first authz paths for RBAC + entitlement + ACL in release candidate
- Confirm audit ledger integrity checks pass before startup and during smoke test
- Confirm production defaults are active (no env-based insecure bypasses)
- Validate secret handling and redaction behavior in logs and command output

## Ops Reliability

- Validate startup/shutdown health on target runtime (service/container)
- Run monitoring and alert smoke checks for critical paths (auth, secret read/write, audit)
- Confirm rotation and key lifecycle commands work in production-like environment
- Ensure capacity and storage limits are reviewed for expected release load

## Backup/Restore Drills

- Create backup and store artifact in approved durable location
- Run restore in non-production environment from latest backup
- Verify post-restore integrity (`audit verify`, secret/object access checks)
- Record Recovery Time Objective (RTO) and Recovery Point Objective (RPO) from drill
- Store drill evidence using conventions in `docs/SRE_SLO_AND_DRILLS.md`

## Incident Response

- Confirm on-call and escalation path are current for production window
- Verify incident runbook access and evidence export flow
- Validate audit trail, timeline, and org-scoped incident commands in dry run
- Capture rollback plan and release owner sign-off before deploy

## Verification Commands

```bash
# Strict system integrity status (required gate)
secretr admin system --strict --format json

# Audit chain verification
secretr audit verify

# Backup lifecycle smoke
secretr backup create --output /tmp/system.backup
secretr backup verify --input /tmp/system.backup

# Incident and monitoring smoke
secretr monitoring health
secretr incident list --format json
```

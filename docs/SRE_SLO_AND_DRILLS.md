# SRE SLO and Drills

Operational governance baseline for production environments.

## Target SLOs

| SLO | Target | Measurement window | Breach trigger |
|---|---|---|---|
| Availability | >= 99.9% monthly uptime for control plane and CLI-backed API workflows | Rolling 30 days | < 99.9% |
| Error rate | <= 1.0% failed requests for critical operations (auth, secret read/write, audit verify) | Rolling 7 days | > 1.0% |
| Backup success | >= 99% successful scheduled backups | Calendar month | < 99% |
| Recovery drill cadence | At least 1 successful restore drill per month per production environment | Calendar month | Missing drill |

## Release Cadence Requirements

- Every production release must include a backup lifecycle check: `backup create`, `backup verify`, and non-prod `backup restore`.
- At least one incident simulation drill must run per quarter; high-risk releases require a targeted tabletop or live drill in the same release window.
- Backup schedule validity must be re-confirmed monthly and after any storage, key, or authz change.
- RTO/RPO measurements must be captured on each drill and compared with prior baseline.

## Required Evidence Checklist

- SLO report snapshot (availability and error-rate metrics for release window).
- Backup evidence: create log, verify output, restore output, artifact checksum/signature metadata.
- Drill evidence: scenario, participants, timeline, actions, RTO/RPO, corrective actions.
- Incident readiness evidence: on-call roster, escalation path, runbook revision date.
- Approval evidence: release owner + SRE sign-off for production promotion.

## Storage Location Conventions

- Use immutable, access-controlled storage and keep evidence by date and environment.
- Recommended path pattern: `evidence/<env>/<yyyy>/<mm>/<release-or-drill-id>/`.
- Recommended files:
  - `slo-report.json`
  - `backup-create.log`
  - `backup-verify.log`
  - `restore-drill.log`
  - `incident-drill.md`
  - `approvals.md`

## Runbook Command Examples

```bash
# System integrity gate
secretr admin system --strict --format json

# Audit integrity and monitoring snapshot
secretr audit verify
secretr monitoring dashboard --period 24h
secretr monitoring events --type authz --limit 200

# Backup lifecycle drill
secretr backup create --output /tmp/release.backup --description "release-drill"
secretr backup verify --input /tmp/release.backup
secretr backup restore --input /tmp/release.backup --include secrets --overwrite

# Incident readiness drill snippets
secretr incident declare --type drill --description "quarterly incident simulation"
secretr incident list
```

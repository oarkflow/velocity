# Secretr Threat Model (Initial)

## Scope
- Secretr CLI/API/GUI under `internal/secretr`.
- Data-at-rest in velocity-backed encrypted store.
- Secret/file sharing, CI/CD OIDC authentication, audit trails.

## Assets
- Master keys and derived encryption keys.
- Secret values and encrypted file payloads.
- Session tokens and CI/CD pipeline tokens.
- Audit chain data and exported evidence.

## Trust Boundaries
- End-user clients (CLI/GUI) -> API/server and local storage.
- External CI/OIDC providers -> CI/CD auth manager.
- Notification providers (webhook/slack/email/pagerduty) -> alert engine.

## Primary Threats
- Token forgery/replay in CI/CD auth.
- Privilege escalation by scope bypass.
- Data exfiltration through misconfigured shares.
- Tampering of audit evidence.
- Misdelivery of alert notifications.

## Implemented Controls
- Scope-gated middleware for command execution.
- Signed/encrypted backup/export and integrity checks.
- Tamper-evident audit/ledger verification paths.
- JWKS-based OIDC signature verification.
- SMTP/webhook/slack/pagerduty notification dispatch controls.

## Required External Controls (Operational)
- Independent penetration test and remediation tracking.
- Network policy and mTLS enforcement in deployment.
- Secrets rotation cadence and break-glass approval workflow.
- Continuous access review and incident tabletop drills.


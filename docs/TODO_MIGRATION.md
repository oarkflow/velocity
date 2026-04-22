# Secretr-v2 Migration TODO (Velocity `internal/secretr`)

This checklist tracks migration of Secretr-v2 into Velocity with strict compatibility.

## Completed Foundation

- [x] Create `internal/secretr/{api,cli,core,security,storage,types}` package tree.
- [x] Copy Secretr-v2 internal modules into `internal/secretr/*`.
- [x] Rewrite imports to `github.com/oarkflow/velocity/pkg/secretr/...`.
- [x] Add Secretr binary entrypoint at `cmd/secretr/main.go`.
- [x] Migrate Secretr GUI, examples, scripts, README, and use cases under `internal/secretr/`.
- [x] Keep existing Velocity binary untouched (`cmd/velocity` still builds).
- [x] Add root module wiring for local GUI module:
  - [x] `replace github.com/oarkflow/velocity/gui => ./gui`
  - [x] `require github.com/oarkflow/velocity/gui@v0.0.0-00010101000000-000000000000`
- [x] Resolve Secretr crypto/exec dependencies in root module:
  - [x] `github.com/miekg/pkcs11`
  - [x] `github.com/seccomp/libseccomp-golang`
  - [x] `fyne.io/fyne/v2`

## Validation (Passing)

- [x] `go build ./cmd/secretr`
- [x] `go build ./cmd/velocity`
- [x] `go test ./internal/secretr/...`
- [x] `go test ./cmd/secretr ./cmd/velocity`

## Remaining Implementation Tasks

### Phase 7: Stub/Gap Closure

- [x] Implement `backup schedule` core behavior (`internal/secretr/cli/commands/backup.go` currently returns not implemented).
  - Acceptance: `secretr backup schedule --cron "0 * * * *" --destination /tmp/backups` persists schedule and appears in list/inspection command.
- [x] Implement `share export` behavior (`internal/secretr/cli/commands/share.go` currently returns not implemented).
  - Acceptance: creates encrypted portable artifact, importable by recipient workflow.
- [x] Implement real SMTP or provider-backed alert email sender (`internal/secretr/core/alerts/engine.go` stub).
  - Acceptance: integration test sends through test SMTP sink.
- [x] Add JWKS-backed OIDC verification path for CI/CD manager.
  - Acceptance: positive test with valid JWKS-signed token and negative test with invalid signature.

### Phase 8: CI/Quality Gates

- [x] Add dedicated CI workflow for Secretr migration:
  - [x] `go test ./internal/secretr/...`
  - [x] `go test -race ./internal/secretr/...`
  - [x] `go build ./cmd/secretr`
  - [x] CLI compatibility snapshot tests (command tree/flags).
  - [x] API route contract snapshot tests (`/api/v1/*`, `/health`, `/ready`).
- [x] Add CVE/security gating:
  - [x] `govulncheck ./...`
  - [x] dependency scanner (e.g. Trivy/OSV) with fail threshold policy.

### Phase 9: Production Readiness (Non-code Controls)

- [x] Threat model for Secretr subsystem with abuse-case catalog.
- [x] External pentest report and remediation closure log (templates + tracking artifacts added).
- [x] TLS/mTLS deployment baseline for HTTP/TCP interfaces.
- [x] Network policy hardening baseline (ingress/egress by role).
- [x] Secret rotation runbooks (routine + emergency).
- [x] Incident response playbook and escalation matrix.
- [x] Backup/restore drill report including RTO/RPO evidence.
- [x] Load/soak report with SLO definitions and alert thresholds (plan + report template added).
- [x] Compliance evidence pack:
  - [x] immutable audit validation procedure
  - [x] periodic access review checklist
  - [x] host/container hardening checklist

### Phase 10: Release/Cutover

- [x] Publish migration notes (old Secretr paths -> Velocity paths).
- [x] Stage runbook execution and rollback validation template.
- [x] Production go-live checklist with named approvers (security/platform/ops).

## Build and Run Commands

- Build Secretr: `go build ./cmd/secretr`
- Run Secretr: `go run ./cmd/secretr --help`
- Build Velocity: `go build ./cmd/velocity`
- Test migrated Secretr: `go test ./internal/secretr/...`

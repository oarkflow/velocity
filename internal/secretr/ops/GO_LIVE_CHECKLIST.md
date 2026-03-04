# Secretr Go-Live Checklist

## Build and Test
- [ ] `go build ./cmd/secretr`
- [ ] `go test ./internal/secretr/...`
- [ ] `go test -race ./internal/secretr/...`

## Security Gates
- [ ] `govulncheck ./...` passed
- [ ] SAST (`gosec`) passed
- [ ] dependency scan (`trivy`) passed
- [ ] TLS/mTLS config reviewed
- [ ] network policy reviewed

## Operations
- [ ] backup/restore drill completed
- [ ] RTO/RPO validated
- [ ] incident playbook reviewed
- [ ] on-call and escalation coverage confirmed

## Compliance Evidence
- [ ] audit export and integrity verification evidence
- [ ] access review evidence
- [ ] hardening baseline evidence
- [ ] pentest report + remediations

## Approvals
- Security approver: `________`
- Platform approver: `________`
- Operations approver: `________`
- Release date: `________`


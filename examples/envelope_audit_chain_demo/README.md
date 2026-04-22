# Envelope Audit Chain Demo

This example validates secure-envelope auditing behaviors end to end:

- access-chain logs intent and recipient-only enforcement
- dependency logs from payload and policy relationships
- custody chain integrity and actor signature checks
- event log style assertions for open success
- automatic logging on envelope operations (import/export/load/unlock), without manual appends

The executable example is implemented as a Go test due to `internal/` package access restrictions.

## Run

```bash
go test ./examples/envelope_audit_chain_demo -v
```

## What it verifies

- recipient-only access (`RecipientID` mismatch is denied)
- envelope signature validation with sender public key
- custody chain hash linkage and per-actor signature verification
- dependency references include policy + payload objects
- automatic operation logs:
  - `envelope.import`
  - `envelope.export`
  - `envelope.load`
  - corresponding custody actions (`envelope.imported`, `envelope.exported`, `envelope.loaded`)

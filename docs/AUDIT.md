# Logging and Auditing Deep-Dive

This document explains Secretr logging and auditing in implementation detail.

It is intended to answer:
- what is logged
- where it is logged
- how events are observed/monitored
- how tamperproof/"temperproof" protections work
- where the current design still has security gaps
- what should be implemented next

## 1. Audit Architecture

Secretr currently has three related layers:

1. Event log layer (`audit_events`)
- append-only audit events
- per-event hash chain (`previous_hash` -> `hash`)

2. Ledger layer (`ledger_blocks`, `ledger_receipts`)
- batched event IDs into blocks
- Merkle root per block
- block chain via `previous_hash`
- inclusion proof receipts per event

3. Monitoring layer (`monitoring_events`)
- near-real-time event stream derived from audit events
- used for dashboards, anomaly/risk flows, and alerts

## 2. What an Audit Event Contains

Audit event schema includes:
- `id`
- `type` (domain/type: `api`, `cli`, `authz`, `secret`, `incident`, `envelope`, etc.)
- `action` (verb or operation)
- `actor_id`, `actor_type`
- optional `resource_id`, `resource_type`
- optional `session_id`, `device_id`
- `timestamp`
- `success` (boolean)
- optional `details` (free metadata)
- optional `ip_address`, `user_agent`
- `previous_hash`, `hash`
- optional `signature`

## 3. Where Events Are Logged

## 3.1 CLI-level logging

Every CLI command action is wrapped and logged with:
- `type=cli`
- `action=command_execute`
- details include command path and error (if failed)

Additionally, command-specific handlers log domain events (for example envelope actions).

## 3.2 API-level logging

Every API request (including denied requests) is logged with:
- `type=api`
- `action=request`
- details: `method`, `path`, `status_code`, `client_ip`, `duration_ms`

Handlers also log domain events (`auth`, `secret`, etc.) for business actions.

## 3.3 Centralized authz decision logging

The deny-first authorizer logs every decision (allow/deny) as:
- `type=authz`
- `action=<operation>` (for example `cli:secret set`, `api:GET:/api/v1/secrets`)
- details include:
  - `denied_by` (`auth|rbac|entitlement|acl|policy|spec`)
  - `reason`
  - `resource_type`
  - `resource_id`
  - `required_scopes`

This provides cross-surface traceability of authorization decisions.

## 4. Event Catalog (Current)

This is the current implemented catalog (major categories).

## 4.1 Platform/meta
- `cli:command_execute`
- `api:request`
- `authz:<dynamic operation>`

## 4.2 Auth and identity flows (API)
- `auth:login`
- `auth:login_failed`
- `auth:logout`

## 4.3 Secret flows (API)
- `secret:create`
- `secret:create_failed`
- `secret:read`
- `secret:read_failed`
- `secret:update`
- `secret:update_failed`
- `secret:delete`
- `secret:delete_failed`

## 4.4 Envelope flows (CLI)
- `envelope:envelope_create`
- `envelope:envelope_create_write_failed`
- `envelope:envelope_open_read_failed`
- `envelope:envelope_open_invalid_format`
- `envelope:envelope_inspect`
- `envelope:envelope_open_password_failed`
- `envelope:envelope_open_key_failed`
- `envelope:envelope_open_denied`
- `envelope:envelope_open`
- `envelope:envelope_verify_read_failed`
- `envelope:envelope_verify_invalid_format`
- `envelope:envelope_verify_failed`
- `envelope:envelope_verify`

## 4.5 CI/CD flows
- `cicd:pipeline_create`
- `cicd:pipeline_auth`
- `cicd:pipeline_auth_oidc`
- `cicd:pipeline_auth_oidc_federated`
- `cicd:secret_inject`
- `cicd:pipeline_revoke`

## 4.6 Incident response flows
- `incident:declare`
- `incident:freeze_access`
- `incident:emergency_rotation`
- `incident:emergency_access_grant`
- `incident:resolve`
- `incident:export_evidence`
- `incident:attestation_report`

## 4.7 SSH flows
- `ssh:profile_create`
- `ssh:session_start`
- `ssh:session_end`
- `ssh:session_terminate`

## 4.8 Execution and file/folder/compliance flows
- `exec:command_execute`
- `folder:upload`
- `folder:download`
- `compliance:assessment_submit`

## 5. Tamperproof / Temperproof Controls

## 5.1 Event hash chain

Each appended event stores:
- `previous_hash` = hash of prior event
- `hash` = hash-chain(previous_hash, current_event_payload)

Verification (`audit verify`) recomputes chain and fails on mismatch.

## 5.2 Merkle ledger chain

Audit event IDs are added to a ledger queue and grouped into blocks.

Each block contains:
- block index
- previous block hash
- Merkle root of event IDs
- block hash
- optional signature
- optional ZK proof metadata

Verification checks:
- previous block linkage
- block re-hash integrity
- signature validity (when signer key configured)

## 5.3 Inclusion receipts

For each event in a block, a receipt with Merkle proof is stored.

This supports proof-of-inclusion workflows for evidence export/verification.

## 5.4 Export signatures

`audit export` returns a signed package when signer key is configured.

## 5.5 Fail-closed startup check

Client initialization verifies both:
- event-store hash chain
- ledger chain integrity

If verification fails, client initialization fails closed.

## 6. Observation and Monitoring Pipeline

Monitoring engine subscribes to audit events and emits monitoring events.

Mapping behavior:
- monitoring `type` is derived from audit `type`
- `source` combines resource/action
- `severity` heuristic:
  - failed events -> `warning`
  - incident type -> `critical`
  - policy violation -> `error`
  - otherwise -> `info`
- risk/success hints are populated in details (`success`, `risk_score`)

This data powers:
- monitoring dashboards
- event queries/streams
- alert processing

## 7. API and CLI Audit Operations

## 7.1 CLI
- `secretr audit query`
- `secretr audit export --output ...`
- `secretr audit verify`

`audit verify` checks:
- hash-chain integrity
- Merkle-ledger integrity
- chain proof summary (block count/latest block info)

## 7.2 API
- `GET /api/v1/audit`
- `GET /api/v1/audit/export`

All API requests are also auto-audited via middleware (`type=api`, `action=request`).

## 8. Important Security Notes and Current Gaps

This section is critical for “secure, tamperproof platform” goals.

1. Signatures are optional and usually not enabled by default
- Event signatures, block signatures, and export signatures depend on signer key configuration.
- If signer key is not configured, integrity relies on hash chains only.

2. Ledger producer is started in API server path
- API `Start()` starts audit block producer.
- CLI-only workflows may accumulate fewer/no ledger blocks until threshold is hit.

3. No external immutable anchor by default
- Audit and ledger are local store collections.
- There is no built-in remote anchor/WORM/notarization target by default.

4. Completeness vs integrity
- Current verification proves internal consistency of available data.
- It does not, by itself, prove no one deleted the entire local store or replaced it with an empty one.

5. Event payload confidentiality discipline
- Most event details are metadata-only.
- Continue avoiding secret plaintext in `details` (envelope already logs payload hash, not payload bytes).

## 9. Threat Scenarios and Expected Behavior

## 9.1 Local event tampering (modify event record)
- Expected: hash-chain verification fails.
- Status: covered.

## 9.2 Ledger block tampering
- Expected: ledger verification fails (hash/link/signature where configured).
- Status: covered.

## 9.3 Unauthorized API/CLI actions
- Expected: denied by authz and logged as `authz` denial + `api:request`/CLI command log.
- Status: covered.

## 9.4 Deleting envelope file
- Envelope custody cannot continue on deleted artifact.
- Envelope-specific audit events still record access attempts when command paths run.
- Status: partially covered; requires stronger storage controls if envelope files are treated as regulated evidence artifacts.

## 9.5 Deleting entire vault/audit store
- Local data loss can remove both events and verification baseline.
- Status: not fully covered without external immutable replication/anchoring.

## 10. Recommended Next Implementations

Priority order for stronger tamperproof posture:

1. Mandatory signer key in production
- enforce startup error when signer key absent in production mode.

2. External anchoring
- periodically anchor latest chain proof/hash to remote immutable target (transparency log, KMS-sign+object-lock storage, or external notarization service).

3. WORM retention
- write audit exports/chain proofs to object lock / append-only storage.

4. Signed checkpoints
- periodic signed checkpoints including event count + latest hash to detect truncation.

5. Strong completeness proofs
- persist monotonic sequence + external checkpoint registry.

6. Alerting on verification failure
- auto-trigger incident/critical alert if startup or periodic verification fails.

7. Dedicated audit policy hardening
- policy gates for high-risk actions: export, delete, restore, envelope open, incident override.

## 11. Operational Runbook

Daily:
```bash
secretr audit verify
secretr audit query --limit 100 --format json
```

Before release/rotation:
```bash
secretr audit export --output /secure/location/audit-export-$(date +%F).json
```

During incident:
```bash
secretr incident timeline --id <INCIDENT_ID>
secretr incident export --id <INCIDENT_ID> --output /secure/location/incident-evidence.json
secretr audit query --action authz --limit 500 --format json
```

## 12. Quick Mapping: “What is observed?”

Observed and auditable today:
- CLI command executions
- API request-level access
- authz allow/deny decisions
- secret CRUD (API path)
- envelope lifecycle operations (CLI path)
- CI/CD auth/injection lifecycle
- incident lifecycle and evidence export
- SSH profile/session lifecycle
- exec command runs
- folder and compliance workflow events

Not yet fully “externally tamperproof” alone:
- full-store deletion/truncation scenarios without external anchors.

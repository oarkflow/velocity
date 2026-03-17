# Envelope Command Deep-Dive

This document is the implementation-level reference for `secretr envelope`.

It covers:
- current command behavior
- security model (RBAC + Entitlement + ACL)
- envelope file format and crypto flow
- audit and chain-of-custody behavior
- known gaps and concrete implementation changes needed

## 1. Command Surface

Top-level group:
- `secretr envelope`

Subcommands:
- `secretr envelope create`
- `secretr envelope open`
- `secretr envelope verify`

## 2. Flags and Arguments

Envelope commands currently use flags only (no positional args).

## 2.1 `secretr envelope create`

Purpose:
- Build an encrypted envelope for a recipient.
- Include secret payloads, files/folders, optional business rules, optional policy id.

Flags:
- Required:
  - `--recipient, -r` (recipient identity id)
  - `--output, -o` (output envelope JSON path)
- Optional:
  - `--secret, -s` (repeatable; `name:value` or `name`)
  - `--file, -f` (repeatable; file or folder path)
  - `--message, -m`
  - `--policy, -p`
  - `--expires-in` (duration)
  - `--require-mfa` (bool)

Positional args:
- none

## 2.2 `secretr envelope open`

Purpose:
- Decrypt and display envelope contents for recipient.
- Optionally inspect metadata/custody without decrypting payload.

Flags:
- Required:
  - `--file, -f` (envelope JSON path)
- Optional:
  - `--inspect` (metadata/custody view only)

Positional args:
- none

## 2.3 `secretr envelope verify`

Purpose:
- Verify custody-chain integrity of envelope file.

Flags:
- Required:
  - `--file, -f` (envelope JSON path)

Positional args:
- none

## 3. Current Access Control and Gating

Envelope commands are gated by deny-first authz (RBAC + Entitlement + ACL).

## 3.1 RBAC Scopes

Required scopes:
- `envelope:create` for `envelope create`
- `envelope:open` for `envelope open`
- `envelope:verify` for `envelope verify`

## 3.2 Entitlement Scopes

Entitlement checks use scope slug == internal scope literal.

Expected license grants:
- feature: `envelope`
- scopes:
  - `envelope:create`
  - `envelope:open`
  - `envelope:verify`

Example entitlement snippet:
```json
{
  "entitlements": {
    "features": {
      "envelope": {
        "feature_slug": "envelope",
        "enabled": true,
        "scopes": {
          "envelope:create": {"scope_slug": "envelope:create", "permission": "allow"},
          "envelope:open": {"scope_slug": "envelope:open", "permission": "allow"},
          "envelope:verify": {"scope_slug": "envelope:verify", "permission": "allow"}
        }
      }
    }
  }
}
```

## 3.3 ACL Behavior (Important)

Resource type is inferred as `envelope`, and ACL is currently required for envelope commands.

Resource-id resolution currently comes from generic flag names (`id`, `name`, `resource`, `file`, `path`, etc).

Practical effect:
- `envelope open` and `envelope verify` normally pass ACL resource-id via `--file`.
- `envelope create` may fail ACL with `resource id required for ACL evaluation` when no `--file` is provided.

This is a current behavior mismatch for create workflows that only include secrets.

## 4. Envelope Data Model

Core model:
- `Envelope`
  - `id`
  - `version`
  - `header`
  - `encrypted_key` (bytes in JSON -> base64 string)
  - `payload` (bytes in JSON -> base64 string)
  - `signature` (bytes in JSON -> base64 string)
  - `custody[]`

- `EnvelopeHeader`
  - `sender_id`
  - `recipient_id`
  - `policy_id` (optional)
  - `business_rules`
  - `created_at`
  - `expires_at`

- `EnvelopePayload`
  - `secrets[]` (`name`, `value`, `type`)
  - `files[]` (`name`, `data`, `type`, `metadata`)
  - `message`

- `CustodyEntry`
  - `hash`
  - `action` (`create|send|open|reject` constants exist)
  - `actor_id`
  - `timestamp`
  - `location`
  - `signature`

## 5. Crypto and Custody Flow

## 5.1 Create flow

1. Build payload JSON from secrets/files/message.
2. Generate random DEK.
3. Encrypt payload with DEK.
4. Generate ephemeral X25519 key pair.
5. Compute shared secret with recipient public key.
6. Encrypt DEK with shared secret.
7. Store `encrypted_key` as `[ephemeral_pub_key || encrypted_DEK]`.
8. Add initial custody entry (`action=create`) signed by sender signing key.
9. Sign envelope package (`header + encrypted_key + payload`) with sender signing key.
10. Write JSON to `--output` (mode `0600`).

## 5.2 Open flow

1. Load envelope file.
2. Validate recipient id match.
3. Validate expiry.
4. Validate business rules (implemented subset).
5. Verify custody chain hash linkage.
6. Derive shared secret from recipient private key + embedded ephemeral pub key.
7. Decrypt DEK, decrypt payload.
8. Attempt to append custody action `open` and rewrite envelope file.
9. Print message, secrets, file/folder entries.

## 5.3 Verify flow

1. Load envelope file.
2. Verify custody chain linkage.
3. Report chain length.

## 6. Business Rules: Supported vs Not Fully Enforced

BusinessRules fields:
- `allowed_time_windows`
- `allowed_ip_ranges`
- `required_trust_level`
- `require_mfa`
- `max_access_count`

Current enforcement in open path:
- enforced:
  - `required_trust_level`
  - `require_mfa`
  - `allowed_time_windows`
- not enforced yet:
  - `allowed_ip_ranges`
  - `max_access_count`

CLI currently exposes only:
- `--require-mfa`

No CLI flags exist yet to set time-window, trust-level, IP ranges, access count.

## 7. Audit and Chain-of-Custody Logging

Envelope CLI emits audit events with type `envelope`.

Current emitted actions include:
- create path:
  - `envelope_create`
  - `envelope_create_write_failed`
- open path:
  - `envelope_open_read_failed`
  - `envelope_open_invalid_format`
  - `envelope_inspect`
  - `envelope_open_password_failed`
  - `envelope_open_key_failed`
  - `envelope_open_denied`
  - `envelope_open`
- verify path:
  - `envelope_verify_read_failed`
  - `envelope_verify_invalid_format`
  - `envelope_verify_failed`
  - `envelope_verify`

Details include file path and hashes where available.

Open success path also attempts custody append (`action=open`) and file rewrite.

## 8. API Coverage Status

There is currently no dedicated envelope REST endpoint documented/implemented in the API server route surface.

Envelope operations are CLI-native currently.

## 9. Current Functional Gaps (Implementation To-Do)

These are real gaps from current code behavior, not wishlist items.

1. Recipient identity input mismatch:
- Flag says `Recipient ID or Email`, but implementation resolves recipient only via identity ID lookup.
- Required change: support email lookup fallback.

2. Policy id not enforced:
- `policy_id` is stored in header but not evaluated in open path.
- Required change: evaluate policy before decrypt/open.

3. Envelope signature not verified on open/verify:
- Create signs envelope, but open/verify does not verify envelope signature.
- Required change: verify envelope signature against sender public signing key.

4. Custody entry signatures are not verified:
- Chain verification checks hash linkage only.
- Required change: verify each custody signature with actor public key (or envelope-defined signer keys).

5. Business rules incomplete:
- `allowed_ip_ranges` and `max_access_count` are declared but not enforced.
- Required change: implement both in `validateRules` + persistent access counters.

6. ACL create-flow friction:
- `envelope create` can require resource-id and fail when no `--file` is provided.
- Required change: define envelope-create ACL resource model explicitly (e.g., recipient/policy object), or disable resource-id-required ACL for create.

7. `--secret name` placeholder behavior:
- `name` without value currently injects literal `placeholder-value`.
- Required change: resolve real secret by name from vault or reject missing value explicitly.

8. Open output leaks secret values to stdout:
- current behavior prints `Secret: name = value`.
- Required change: add masked/default-safe output mode and explicit reveal flag.

9. Non-fatal custody append persistence:
- open path ignores errors when appending custody or rewriting file.
- Required change: decide strict mode (fail if custody write fails) vs permissive mode with explicit warning/audit.

10. No dedicated envelope API surface:
- Required change: implement API endpoints for create/open/verify/inspect with same authz, audit, and custody semantics.

## 10. Recommended Implementation Sequence

1. Security correctness first:
- signature verification (envelope + custody)
- policy enforcement
- business rule completion

2. Authz correctness:
- ACL resource model for create
- recipient id/email behavior

3. Data handling safety:
- remove placeholder secret behavior
- add safe output controls

4. Platform parity:
- add envelope API endpoints
- add parity tests (CLI vs API) for all envelope flows

## 11. Test Coverage Status

Current core tests cover:
- basic create/open workflow
- expired envelope denial
- MFA business rule

Missing tests to add:
- signature tampering rejection
- custody signature tampering rejection
- IP range and access count rule enforcement
- policy enforcement on open
- ACL behavior for create/open/verify
- recipient email resolution
- strict/non-strict custody persistence behavior

## 12. Quick Practical Commands

Create:
```bash
secretr envelope create \
  --recipient <RECIPIENT_ID> \
  --secret API_KEY:abc123 \
  --file /tmp/secret.txt \
  --message "incident payload" \
  --require-mfa \
  --expires-in 24h \
  --output /tmp/env.json
```

Inspect:
```bash
secretr envelope open --file /tmp/env.json --inspect
```

Open:
```bash
secretr envelope open --file /tmp/env.json
```

Verify:
```bash
secretr envelope verify --file /tmp/env.json
```

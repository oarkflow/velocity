# SHARE Command Deep-Dive

This document is the implementation-level reference for `secretr share`.

It covers:
- real behavior from current code
- required vs optional flags and positional args
- expected resource resolution and offline package behavior
- RBAC + entitlement + ACL gating
- API parity and known defects

## 1. Command Surface

Top-level group:
- `secretr share`

Subcommands:
- `secretr share create`
- `secretr share list`
- `secretr share revoke`
- `secretr share accept`
- `secretr share export`

Implementation sources:
- `internal/secretr/cli/commands/share.go`
- `internal/secretr/core/share/manager.go`

## 2. Share Model and Behavior

Supported share types:
- `secret`
- `file`
- `object`
- `folder`

Create behavior:
- validates target resource exists before creating share
- recipient is optional
- if recipient is omitted, share is not recipient-bound
- supports expiration (`--expires-in`), max access count (`--max-access`), and one-time usage (`--one-time`)

Access behavior (`accept`):
- fails if share revoked or expired
- fails for one-time share already used
- fails if max access count reached
- if recipient is set, accessor must match recipient
- increments `access_count` and sets `accessed_at`

Export behavior (`export`):
- fetches share payload bytes based on share type
- requires recipient public key for offline package encryption
- recipient key source order:
  1. `share.recipient_key`
  2. recipient identity public key (if recipient ID is present)
- output file is written with mode `0600`

Offline package format:
- JSON of `share.OfflinePackage`
- fields include:
  - `id`
  - `share_id`
  - `encrypted_data`
  - `encrypted_key`
  - `recipient_pub_key`
  - `hash`
  - `signature`
  - `created_at`
  - `expires_at`

## 3. Flags Matrix (Required vs Optional)

### `secretr share`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr share create`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--type` | yes | `string` | `secret|file|folder|object` |
| `--resource`, `-r` | yes | `string` | resource ID/path/name |
| `--recipient` | no | `string` | recipient identity ID |
| `--expires-in` | no | `duration` | share expiration |
| `--max-access` | no | `int` | max successful accesses |
| `--one-time` | no | `bool` | allows one successful access |

### `secretr share list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | lists shares created by current identity |

### `secretr share revoke`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--id` | yes | `string` | share ID |

### `secretr share accept`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--id` | yes | `string` | share ID |

### `secretr share export`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--id` | yes | `string` | share ID |
| `--output`, `-o` | yes | `string` | output package path |

## 4. Positional Arguments Matrix

All share commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr share` | none | none |
| `secretr share create` | none | none |
| `secretr share list` | none | none |
| `secretr share revoke` | none | none |
| `secretr share accept` | none | none |
| `secretr share export` | none | none |

## 5. Copy-Paste Use Cases

Create share for secret:
```bash
secretr share create \
  --type secret \
  --resource ENCRYPTED_SECRET \
  --recipient <RECIPIENT_ID> \
  --expires-in 24h \
  --max-access 3
```

Create one-time folder share:
```bash
secretr share create --type folder --resource /apps/demo --one-time
```

List your created shares:
```bash
secretr share list
```

Accept incoming share:
```bash
secretr share accept --id <SHARE_ID>
```

Export share for offline transfer:
```bash
secretr share export --id <SHARE_ID> --output ./offline-share.json
```

Revoke share:
```bash
secretr share revoke --id <SHARE_ID>
```

## 6. RBAC + Entitlement + ACL

Current manifest scopes:
- `share create` -> `share:create`
- `share list` -> `share:read`
- `share revoke` -> `share:revoke`
- `share accept` -> `share:accept`
- `share export` -> `share:export`

Entitlements:
- matching `scope_slug` values are required
- deny-first checks enforce `RBAC && Entitlement && ACL`

ACL behavior:
- resource type resolves to `share`
- resource IDs come from `--id`/`--resource` when available
- list operations may hit collection-level ACL edge cases in strict setups

## 7. API Parity

No dedicated REST routes for share operations currently.

Only generic command-dispatch route exists:
- `POST /api/v1/commands/share/...`
- currently returns `not_implemented`

## 8. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz`
- API request audit: `type=api`, `action=request` (for REST usage)

## 9. Known Gaps and Defects

1. Missing `defer c.Close()` in `ShareExport`:
- other share handlers close client; export currently does not

2. Resharing control not surfaced in CLI create:
- manager supports resharing metadata policy, but CLI create lacks explicit control for it

3. API parity missing:
- share-specific HTTP endpoints are not implemented

4. Collection ACL friction:
- `share list` has no single resource ID and may deny under strict ACL rule sets

## 10. Recommended Fixes

1. Add `defer c.Close()` in `ShareExport` for consistency.
2. Add explicit `--allow-reshare` (or deny-by-default metadata) in `share create`.
3. Implement dedicated `/api/v1/shares` endpoints (create/list/accept/revoke/export).
4. Add collection-level ACL policy for list operations.

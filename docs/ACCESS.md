# ACCESS Command Deep-Dive

This document is the implementation-level reference for `secretr access`.

It covers:
- real behavior from current handlers
- required vs optional flags and positional args
- grant and JIT request semantics
- RBAC + entitlement + ACL behavior
- known security and parity gaps

## 1. Command Surface

Top-level group:
- `secretr access`

Subcommands:
- `secretr access grant`
- `secretr access revoke`
- `secretr access list`
- `secretr access request`
- `secretr access approve`

Implementation sources:
- `internal/secretr/cli/commands/acl.go`
- `internal/secretr/core/access/manager.go`

## 2. Access Model and Behavior

Grant model:
- creates `types.AccessGrant` with:
  - `grantor_id`, `grantee_id`
  - `resource_id`, `resource_type`
  - `scopes[]`
  - optional `expires_at`
  - optional conditions (`RequireApproval` etc.)
  - `resharing_allowed`

Check behavior in manager:
- if explicit grants exist for actor+resource, scopes/conditions are enforced
- if no explicit grant exists for actor+resource, manager currently allows by default
- this means ACL manager is permissive unless grant records exist

JIT request behavior:
- `access request` creates pending access request
- `duration` stored as string and parsed during approval
- if duration parse fails on approval, defaults to `1h`
- `approve` increments approval count and creates grant when threshold met

## 3. Flags Matrix (Required vs Optional)

### `secretr access`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr access grant`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--grantee`, `-g` | yes | `string` | grantee identity ID |
| `--resource`, `-r` | yes | `string` | resource ID |
| `--type` | no | `string` | resource type (secret/file/key etc.) |
| `--scopes`, `-s` | no | `string[]` | granted scopes |
| `--expires-in` | no | `duration` | optional TTL |
| `--resharing` | no | `bool` | allow grantee resharing |

### `secretr access revoke`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--id` | yes | `string` | grant ID |

### `secretr access list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--resource` | no | `string` | resource filter |
| `--grantee` | no | `string` | grantee filter |

### `secretr access request`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--resource` | yes | `string` | resource ID |
| `--type` | yes | `string` | resource type |
| `--justification` | yes | `string` | why access is needed |
| `--duration` | yes | `string` | e.g. `30m`, `2h` |

### `secretr access approve`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--id` | yes | `string` | access request ID |

## 4. Positional Arguments Matrix

All access commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr access` | none | none |
| `secretr access grant` | none | none |
| `secretr access revoke` | none | none |
| `secretr access list` | none | none |
| `secretr access request` | none | none |
| `secretr access approve` | none | none |

## 5. Copy-Paste Use Cases

Grant scoped access:
```bash
secretr access grant \
  --grantee <IDENTITY_ID> \
  --resource ENCRYPTED_SECRET \
  --type secret \
  --scopes secret:read \
  --expires-in 2h
```

List grants:
```bash
secretr access list
secretr access list --resource ENCRYPTED_SECRET
```

Revoke grant:
```bash
secretr access revoke --id <GRANT_ID>
```

Request JIT access:
```bash
secretr access request \
  --resource ENCRYPTED_SECRET \
  --type secret \
  --justification "Production break-fix" \
  --duration 1h
```

Approve JIT request:
```bash
secretr access approve --id <REQUEST_ID>
```

## 6. RBAC + Entitlement + ACL

Current manifest scopes:
- `access grant` -> `access:grant`
- `access revoke` -> `access:revoke`
- `access list` -> `access:read`
- `access request` -> `access:request`
- `access approve` -> `access:approve`

Entitlement scopes must match these values.

ACL behavior:
- resource type resolves to `access`
- resource id resolved from `--id` or `--resource` when present
- deny-first authz still applies globally (`RBAC && Entitlement && ACL`)

## 7. API Parity

No dedicated `/api/v1/access` REST routes currently.

Only command-dispatch route exists:
- `POST /api/v1/commands/access/...`
- currently returns `not_implemented`

## 8. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz`
- API request audit: `type=api`, `action=request`

## 9. Known Gaps and Defects

1. ACL manager is allow-by-default when no explicit grant exists:
- `access.Manager.Check` returns allow when no actor+resource grant record is found

2. `access request` and `access approve` handlers do not call `RequireScope` internally:
- they rely on outer middleware/authz gating only

3. Hidden dead command logic:
- `AccessCheck` function exists in code but no CLI command is wired for it

4. API parity missing:
- no direct REST endpoints for grant/request/approve/revoke/list

## 10. Recommended Fixes

1. Move ACL manager to explicit deny-by-default mode for protected resource types.
2. Add in-handler scope checks for `request` and `approve` as defense-in-depth.
3. Either wire `access check` command or remove dead function.
4. Implement `/api/v1/access` endpoints and parity tests.

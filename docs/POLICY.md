# POLICY Command Deep-Dive

This document is the implementation-level reference for `secretr policy`.

It covers:
- real current behavior from handlers/engine
- required vs optional flags and positional args
- expected policy file schema (JSON/YAML)
- RBAC + entitlement + ACL gating
- implementation gaps and security implications

## 1. Command Surface

Top-level group:
- `secretr policy`

Subcommands:
- `secretr policy create`
- `secretr policy list`
- `secretr policy bind`
- `secretr policy simulate`
- `secretr policy freeze`

Implementation sources:
- `internal/secretr/cli/commands/policy.go`
- `internal/secretr/core/policy/engine.go`

## 2. Policy Model and Enforcement

Policy object fields:
- `id`, `name`, `description`, `version`, `type`, `rules[]`
- optional signature fields (`signature`, `signed_by`)

Supported `type` values:
- `access`
- `rotation`
- `retention`
- `approval`
- `compliance`

Rule model (`types.PolicyRule`):
- `id`
- `effect`: `allow` or `deny` (required)
- `actions[]` (required, supports glob-style matching)
- `resources[]` (optional; empty means all resources)
- `conditions` (metadata map)
- `priority` (currently not used by evaluator ordering)

Evaluation behavior:
- bindings are fetched by resource ID
- matching `deny` rule sets evaluation result to denied
- `allow` rules do not currently short-circuit or override deny

Freeze behavior:
- `policy freeze` sets engine frozen mode
- frozen mode blocks create/update/bind operations

## 3. Policy File Schema (`--file`)

Supported file types:
- `.json`
- `.yaml` / `.yml`

Top-level file structure:
```json
{
  "description": "Human readable description",
  "type": "access",
  "rules": [
    {
      "id": "rule-1",
      "effect": "deny",
      "actions": ["secret:read", "secret:update"],
      "resources": ["prod/*"],
      "conditions": {
        "require_mfa": true
      },
      "priority": 100
    }
  ]
}
```

YAML equivalent:
```yaml
description: Block direct prod secret reads
type: access
rules:
  - id: deny-prod-read
    effect: deny
    actions:
      - secret:read
    resources:
      - prod/*
    conditions:
      require_mfa: true
    priority: 100
```

Validation currently enforced:
- `effect` must be `allow` or `deny`
- `actions` must be non-empty

## 4. Flags Matrix (Required vs Optional)

### `secretr policy`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr policy create`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--name`, `-n` | yes | `string` | policy name |
| `--file`, `-f` | no | `string` | JSON/YAML definition file |

### `secretr policy list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | list all policies |

### `secretr policy bind`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--policy` | yes | `string` | policy ID |
| `--resource` | yes | `string` | resource ID |

### `secretr policy simulate`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--policy` | yes | `string` | policy ID to verify existence |
| `--action` | yes | `string` | action string to simulate |
| `--resource` | no | `string` | resource ID target |

### `secretr policy freeze`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | prompts confirmation first |

## 5. Positional Arguments Matrix

All policy commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr policy` | none | none |
| `secretr policy create` | none | none |
| `secretr policy list` | none | none |
| `secretr policy bind` | none | none |
| `secretr policy simulate` | none | none |
| `secretr policy freeze` | none | none |

## 6. Copy-Paste Use Cases

Create from JSON file:
```bash
cat > ./policy.json <<'JSON'
{
  "description": "Deny prod secret reads",
  "type": "access",
  "rules": [
    {
      "id": "deny-prod-read",
      "effect": "deny",
      "actions": ["secret:read"],
      "resources": ["prod/*"],
      "priority": 100
    }
  ]
}
JSON

secretr policy create --name "prod-guard" --file ./policy.json
```

List policies:
```bash
secretr policy list
```

Bind policy to resource:
```bash
secretr policy bind --policy <POLICY_ID> --resource prod/db/password
```

Simulate action:
```bash
secretr policy simulate --policy <POLICY_ID> --action secret:read --resource prod/db/password
```

Freeze policy engine:
```bash
secretr policy freeze
```

## 7. RBAC + Entitlement + ACL

Current manifest scopes:
- `policy create` -> `policy:create`
- `policy list` -> `policy:read`
- `policy bind` -> `policy:bind`
- `policy simulate` -> `policy:simulate`
- `policy freeze` -> `policy:freeze` and `admin:*`

Entitlements must include matching scope slugs.

ACL behavior:
- resource type resolves to `policy`
- resource id from `--policy`/`--resource` when present
- deny-first authz path applies globally

## 8. API Parity

No dedicated `/api/v1/policies` REST routes currently.

Only generic command dispatch exists:
- `POST /api/v1/commands/policy/...`
- currently returns `not_implemented`

## 9. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz`
- API request audit: `type=api`, `action=request`

## 10. Known Gaps and Defects

1. `policy bind` missing `--type` CLI flag:
- handler reads `cmd.String("type")` but command definition does not expose `--type`
- bindings are stored with empty `resource_type`

2. `policy freeze` lacks in-handler scope check:
- command relies on outer middleware only

3. Signature verification path is not exposed via CLI command:
- engine has `VerifySignature`, but no user command invokes it

4. No dedicated policy REST API endpoints

## 11. Recommended Fixes

1. Add required `--type` flag to `policy bind` and validate allowed resource types.
2. Add in-handler scope check in `PolicyFreeze` as defense-in-depth.
3. Add `policy verify-signature` CLI command (and API equivalent).
4. Implement `/api/v1/policies` CRUD/bind/simulate endpoints with parity tests.

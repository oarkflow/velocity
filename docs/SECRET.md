# SECRET Command Deep-Dive

This document is the implementation-level reference for `secretr secret`.

It covers:
- real command behavior from current code
- required vs optional flags and positional args
- expected input shapes (plain, JSON, nested dot-notation)
- RBAC + entitlement + ACL gating behavior
- API parity and known implementation gaps

## 1. Command Surface

Top-level group:
- `secretr secret`

Subcommands:
- `secretr secret set`
- `secretr secret get`
- `secretr secret list`
- `secretr secret delete`
- `secretr secret rotate`

Backend implementation source:
- `cli/commands/secret.go`
- wrapped by `internal/secretr/cli/commands/velocity_wrapper.go`

## 2. Storage Model and Data Semantics

Secret storage key format:
- `secret:<category>:<name>`

Default category:
- `general`

Value forms accepted by `secret set --value`:
- plain string
- JSON object
- JSON array
- JSON scalar (`true`, `123`, `null`)

Dot-notation behavior (`--name`):
- `app.db.password` is split into root key `app` and nested path `db.password`
- stored record key becomes `secret:<category>:app`
- nested JSON is merged/updated under that root

Example stored JSON for:
- `--name app.db.password --value '"hello"'`

Result under key `secret:general:app`:
```json
{
  "db": {
    "password": "hello"
  }
}
```

## 3. Flags Matrix (Required vs Optional)

### `secretr secret`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr secret set`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--name`, `-n` | yes | `string` | secret name; supports dot-notation |
| `--value`, `-v` | yes | `string` | plain or JSON value |
| `--ttl`, `-t` | no | `int` | seconds, `0` means no expiry |
| `--category`, `-c` | no | `string` | default `general` |

### `secretr secret get`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--name`, `-n` | yes | `string` | supports dot-notation lookup |
| `--category`, `-c` | no | `string` | default `general` |
| `--show`, `-s` | no | `bool` | show plaintext; default masked |

### `secretr secret list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--category`, `-c` | no | `string` | filters by category |

### `secretr secret delete`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--name`, `-n` | yes | `string` | exact key name used for deletion |
| `--category`, `-c` | no | `string` | default `general` |

### `secretr secret rotate`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--name`, `-n` | yes | `string` | target secret key |
| `--category`, `-c` | no | `string` | default `general` |
| `--length`, `-l` | no | `int` | random bytes before hex-encoding; default `32` |

## 4. Positional Arguments Matrix

All secret commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr secret` | none | none |
| `secretr secret set` | none | none |
| `secretr secret get` | none | none |
| `secretr secret list` | none | none |
| `secretr secret delete` | none | none |
| `secretr secret rotate` | none | none |

## 5. Copy-Paste Use Cases

Initialize and login:
```bash
secretr auth init --email=you@example.com --name="You"
secretr auth login --email=you@example.com
```

Set and read simple value:
```bash
secretr secret set --name="ENCRYPTED_SECRET" --value="hello"
secretr secret get --name="ENCRYPTED_SECRET" --show
```

Store nested JSON via dot-notation:
```bash
secretr secret set --name="processgate.aws.client_id" --value='"abc123"'
secretr secret set --name="processgate.aws.secret" --value='"topsecret"'
secretr secret get --name="processgate" --show
```

Store full JSON object directly:
```bash
secretr secret set --name="processgate" --value='{"aws":{"client_id":"abc123","secret":"topsecret"}}'
secretr secret get --name="processgate" --show
```

List by category:
```bash
secretr secret list --category=general
```

Rotate secret value:
```bash
secretr secret rotate --name="ENCRYPTED_SECRET" --length=48
```

## 6. RBAC + Entitlement + ACL

Current scope expectations (manifest):
- `secret set` -> `secret:update`
- `secret get` -> `secret:read`
- `secret list` -> `secret:list`
- `secret delete` -> `secret:delete`
- `secret rotate` -> `secret:rotate`

Entitlements must include matching `scope_slug` values with `allow` (or valid `limit`).

ACL behavior:
- resource type resolves to `secret`
- resource id is resolved from flags such as `--name`
- deny-first enforcement: `RBAC && Entitlement && ACL` must all pass

## 7. API Parity

Implemented REST routes:
- `GET /api/v1/secrets`
- `POST /api/v1/secrets`
- `GET /api/v1/secrets/{name}`
- `PUT /api/v1/secrets/{name}`
- `DELETE /api/v1/secrets/{name}`

Command-dispatch route:
- `POST /api/v1/commands/<path>` exists
- command dispatch handler currently returns `not_implemented`

## 8. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz` allow/deny per operation
- API request audit: `type=api`, `action=request` on REST usage

## 9. Known Gaps and Defects

1. Dot-notation delete mismatch:
- `set` with `a.b.c` stores under root key `a`
- `delete --name a.b.c` deletes key `secret:<cat>:a.b.c` (different key)

2. Dot-notation rotate mismatch:
- `rotate --name a.b.c` writes key `secret:<cat>:a.b.c`
- this does not rotate nested value under existing root-key JSON

3. `secret list` ACL friction:
- list has no natural single resource id
- strict ACL requiring resource id can deny list in some policy setups

4. Command/API parity is incomplete for dispatch endpoint:
- route exists but does not execute command handlers yet

## 10. Recommended Fixes

1. Normalize `delete` and `rotate` to same root-key + nested-path model as `set/get`.
2. Add dedicated ACL semantics for list operations (collection-level ACL) to avoid false denies.
3. Implement command dispatch execution path with full authz + audit + argument validation.
4. Add regression tests for dot-notation set/get/delete/rotate consistency.

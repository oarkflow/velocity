# OBJECT Command Deep-Dive

This document is the implementation-level reference for `secretr object`.

It covers:
- real behavior from current command handlers
- required vs optional flags and positional args
- expected file/tag inputs
- RBAC + entitlement + ACL behavior
- API parity and implementation gaps

## 1. Command Surface

Top-level group:
- `secretr object`

Subcommands:
- `secretr object put`
- `secretr object get`
- `secretr object delete`
- `secretr object list`
- `secretr object info`
- `secretr object view`

Backend implementation source:
- `cli/commands/object.go`
- wrapped by `internal/secretr/cli/commands/velocity_wrapper.go`

## 2. Behavior and Input Expectations

Object path:
- logical vault/object path, passed via `--path`

Upload source:
- local file path via `--file`

Tags format (`--tag` repeatable):
- `key=value`
- if `=` is missing, value becomes empty string

Encryption:
- `put` default `--encrypt=true`

Content type:
- auto-detected from file extension when `--content-type` not provided
- fallback is `application/octet-stream`

## 3. Flags Matrix (Required vs Optional)

### `secretr object`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr object put`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | destination object path in vault |
| `--file`, `-f` | yes | `string` | local source file |
| `--content-type`, `-c` | no | `string` | override detected content type |
| `--encrypt`, `-e` | no | `bool` | default `true` |
| `--tag`, `-t` | no | `string[]` | repeatable `key=value` tags |

### `secretr object get`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | object path in vault |
| `--output`, `-o` | yes | `string` | local output file path |

### `secretr object delete`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | object path in vault |
| `--user`, `-u` | no | `string` | declared but not actually consumed by handler logic |

### `secretr object list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--prefix`, `-p` | no | `string` | key prefix filter |
| `--folder`, `-f` | no | `string` | folder filter |
| `--recursive`, `-r` | no | `bool` | recursive listing |
| `--limit`, `-l` | no | `int` | default `100` |

### `secretr object info`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | object path in vault |

### `secretr object view`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | object path in vault |
| `--user`, `-u` | no | `string` | declared but handler reads root `--user` instead |

## 4. Positional Arguments Matrix

All object commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr object` | none | none |
| `secretr object put` | none | none |
| `secretr object get` | none | none |
| `secretr object delete` | none | none |
| `secretr object list` | none | none |
| `secretr object info` | none | none |
| `secretr object view` | none | none |

## 5. Copy-Paste Use Cases

Upload object with tags:
```bash
secretr object put \
  --path "/apps/demo/config.json" \
  --file "./config.json" \
  --content-type "application/json" \
  --tag app=demo \
  --tag tier=backend
```

Download object:
```bash
secretr object get --path "/apps/demo/config.json" --output "./downloaded-config.json"
```

Inspect metadata:
```bash
secretr object info --path "/apps/demo/config.json"
```

List recursively under prefix:
```bash
secretr object list --prefix "/apps/demo" --recursive --limit 500
```

Delete object:
```bash
secretr object delete --path "/apps/demo/config.json"
```

Open preview:
```bash
secretr object view --path "/apps/demo/readme.md"
```

## 6. RBAC + Entitlement + ACL

Current expected scopes from authz manifest:
- `object list` -> `file:list`
- `object delete` -> `file:delete`
- `object get` -> `file:list` (see gap below)
- `object put` -> `file:list` (see gap below)
- `object info` -> `file:list`
- `object view` -> `file:list` (see gap below)

ACL behavior:
- resource type resolves to `file`
- resource id resolves from flags (`--path`, `--file`, etc.)
- deny-first: `RBAC && Entitlement && ACL`

## 7. API Parity

Low-level file routes exist:
- `GET /api/v1/files`
- `POST /api/v1/files`
- `GET /api/v1/files/{name}`
- `DELETE /api/v1/files/{name}`

Object-group command dispatch:
- `POST /api/v1/commands/object/...` path exists
- current dispatch handler returns `not_implemented`

## 8. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz`
- API request audit for REST file routes: `type=api`, `action=request`

## 9. Known Gaps and Defects

1. Scope mapping mismatch for object subcommands:
- manifest currently maps `put/get/view` to `file:list`
- expected should differentiate `file:upload` / `file:download`

2. `--user` flag inconsistency:
- `delete` and `view` define local `--user`
- handler reads `c.Root().String("user")`, so local subcommand flag may not affect behavior

3. Collection ACL ambiguity:
- list operations are collection-level, but generic resource-id ACL may deny in strict policy settings

4. Command dispatch API path is not implemented:
- route exists but does not execute command handlers

## 10. Recommended Fixes

1. Correct command scope manifest for `object put/get/view` to upload/download scopes.
2. Standardize user resolution (`local --user` vs root hidden `--user`) and test it.
3. Add collection-level ACL handling for list operations.
4. Implement command dispatch execution with strict authz, schema validation, and audit.

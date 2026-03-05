# FOLDER Command Deep-Dive

This document is the implementation-level reference for `secretr folder`.

It covers:
- real behavior from current handlers
- required vs optional flags and positional args
- expected input for create/upload/copy/rename/view flows
- RBAC + entitlement + ACL behavior
- API parity and known defects

## 1. Command Surface

Top-level group:
- `secretr folder`

Subcommands:
- `secretr folder create`
- `secretr folder upload`
- `secretr folder list`
- `secretr folder info`
- `secretr folder delete`
- `secretr folder copy`
- `secretr folder rename`
- `secretr folder size`
- `secretr folder view`

Backend implementation source:
- `cli/commands/folder.go`
- wrapped by `internal/secretr/cli/commands/velocity_wrapper.go`

## 2. Behavior and Input Expectations

Folder paths:
- logical vault folder paths via `--path`, `--source`, `--dest`, `--old`, `--new`

Upload behavior:
- source must exist and be a local directory
- destination path is normalized to start with `/`
- recursively walks local tree by default (`--recursive=true`)
- uploads each file as object with inferred content type

Delete behavior:
- non-recursive delete expects empty folder
- recursive delete removes folder and all contents

View behavior:
- opens preview flow for folder contents
- `--max-file-size` is MB and converted to bytes internally

## 3. Flags Matrix (Required vs Optional)

### `secretr folder`

| Flag | Required | Type | Notes |
|---|---|---|---|
| none | - | - | top-level group command |

### `secretr folder create`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | single-folder create path |
| `--paths`, `-m` | no | `string[]` | additional paths for batch create |
| `--user`, `-u` | no | `string` | declared, but handler reads root `--user` |

### `secretr folder upload`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--source`, `-s` | yes | `string` | local folder path |
| `--dest`, `-d` | yes | `string` | destination vault folder |
| `--encrypt`, `-e` | no | `bool` | default `true` |
| `--recursive`, `-r` | no | `bool` | default `true` |

### `secretr folder list`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--parent`, `-p` | no | `string` | parent path filter |
| `--recursive`, `-r` | no | `bool` | recursive listing |

### `secretr folder info`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | folder path |

### `secretr folder delete`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | folder path |
| `--recursive`, `-r` | no | `bool` | delete all contents |
| `--user`, `-u` | no | `string` | declared, but handler reads root `--user` |

### `secretr folder copy`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--source`, `-s` | yes | `string` | source folder path |
| `--dest`, `-d` | yes | `string` | destination folder path |
| `--user`, `-u` | no | `string` | declared, but handler reads root `--user` |

### `secretr folder rename`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--old`, `-o` | yes | `string` | source/old folder path |
| `--new`, `-n` | yes | `string` | destination/new folder path |
| `--user`, `-u` | no | `string` | declared, but handler reads root `--user` |

### `secretr folder size`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | folder path |
| `--recursive`, `-r` | no | `bool` | default `true` |

### `secretr folder view`

| Flag | Required | Type | Notes |
|---|---|---|---|
| `--path`, `-p` | yes | `string` | folder path in vault |
| `--compress`, `-c` | no | `bool` | compress text files for preview |
| `--max-file-size` | no | `int64` | MB, default `100` |

## 4. Positional Arguments Matrix

All folder commands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr folder` | none | none |
| `secretr folder create` | none | none |
| `secretr folder upload` | none | none |
| `secretr folder list` | none | none |
| `secretr folder info` | none | none |
| `secretr folder delete` | none | none |
| `secretr folder copy` | none | none |
| `secretr folder rename` | none | none |
| `secretr folder size` | none | none |
| `secretr folder view` | none | none |

## 5. Copy-Paste Use Cases

Create folder:
```bash
secretr folder create --path "/apps/demo"
```

Batch create folders:
```bash
secretr folder create --path "/apps/demo" --paths "/apps/demo/config" --paths "/apps/demo/logs"
```

Upload local directory:
```bash
secretr folder upload --source "./fixtures/demo" --dest "/apps/demo" --recursive --encrypt
```

List folders recursively:
```bash
secretr folder list --parent "/apps" --recursive
```

Folder metadata:
```bash
secretr folder info --path "/apps/demo"
```

Compute size:
```bash
secretr folder size --path "/apps/demo" --recursive
```

Copy and rename:
```bash
secretr folder copy --source "/apps/demo" --dest "/apps/demo-copy"
secretr folder rename --old "/apps/demo-copy" --new "/apps/demo-v2"
```

Delete recursively:
```bash
secretr folder delete --path "/apps/demo-v2" --recursive
```

Preview folder:
```bash
secretr folder view --path "/apps/demo" --max-file-size 200 --compress
```

## 6. RBAC + Entitlement + ACL

Current expected scopes from authz manifest:
- `folder create` -> `file:upload`
- `folder upload` -> `file:upload`
- `folder list` -> `file:list`
- `folder info` -> `file:list`
- `folder delete` -> `file:delete`
- `folder copy` -> `file:upload`
- `folder rename` -> `file:upload`
- `folder size` -> `file:list`
- `folder view` -> `file:download`

ACL behavior:
- resource type resolves to `folder`
- resource id typically resolves from path-like flags
- deny-first model: `RBAC && Entitlement && ACL`

## 7. API Parity

No dedicated `/api/v1/folders` route currently.

Closest APIs:
- low-level object routes under `/api/v1/files`
- command-dispatch route `/api/v1/commands/folder/...` exists but currently returns `not_implemented`

## 8. Audit and Observability

Observed layers:
- CLI command audit: `type=cli`, `action=command_execute`
- authz decision audit: `type=authz`
- API request audit for REST routes: `type=api`, `action=request`

## 9. Known Gaps and Defects

1. `--user` local flag inconsistency:
- several subcommands define `--user`
- handlers read root hidden `--user`, so local `--user` may be ignored

2. Batch create friction:
- `create` requires `--path` even when `--paths` batch list is supplied

3. Collection ACL ambiguity:
- `folder list` may be denied in strict ACL configurations without a single resource id

4. API command dispatch for folder operations is not implemented yet

## 10. Recommended Fixes

1. Standardize `--user` handling so command-local user input is respected consistently.
2. Allow pure batch mode for `folder create` without mandatory `--path`.
3. Add explicit collection-level ACL semantics for list operations.
4. Implement `/api/v1/commands/folder/...` execution path with full authz + audit.

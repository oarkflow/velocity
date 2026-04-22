# DATA Command Deep-Dive

This document is implementation-oriented guidance for the `secretr data` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr data` | Manage key-value data storage |
| `secretr data delete` | Delete data from the database |
| `secretr data exists` | Check if key exists in the database |
| `secretr data get` | Get data from the database |
| `secretr data index` | Store data and build search indexes |
| `secretr data list` | List keys in the database |
| `secretr data put` | Store data in the database |
| `secretr data search` | Search values using full-text and filters |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr data` | `file:list` |
| `secretr data delete` | `file:delete` |
| `secretr data exists` | `file:list` |
| `secretr data get` | `file:list` |
| `secretr data index` | `file:list` |
| `secretr data list` | `file:list` |
| `secretr data put` | `file:list` |
| `secretr data search` | `file:list` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr data` | `file` | yes |
| `secretr data delete` | `file` | yes |
| `secretr data exists` | `file` | yes |
| `secretr data get` | `file` | yes |
| `secretr data index` | `file` | yes |
| `secretr data list` | `file` | yes |
| `secretr data put` | `file` | yes |
| `secretr data search` | `file` | yes |

## 4. Flags and Positional Arguments

### `secretr data`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data delete`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--key` | `-k` | `string` | yes | `sensitive` | no | Key name |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data exists`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--key` | `-k` | `string` | yes | `sensitive` | no | Key name |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data get`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--json` | `-j` | `bool` | no | `control` | no | Format output as JSON |
| `--key` | `-k` | `string` | yes | `sensitive` | no | Key name |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data index`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--json` | `-j` | `bool` | no | `control` | no | Parse value as JSON |
| `--key` | `-k` | `string` | yes | `sensitive` | no | Key name |
| `--prefix` | - | `string` | no | `control` | no | Prefix namespace for schema (e.g. users) |
| `--schema` | - | `string` | no | `control` | no | JSON schema for indexing (SearchSchema) |
| `--value` | `-v` | `string` | yes | `control` | no | Value to store |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--limit` | `-l` | `int` | no | `control` | no | Limit number of keys |
| `--offset` | `-o` | `int` | no | `control` | no | Offset for pagination |
| `--prefix` | `-p` | `string` | no | `control` | no | Filter keys by prefix |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data put`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--json` | `-j` | `bool` | no | `control` | no | Parse value as JSON |
| `--key` | `-k` | `string` | yes | `sensitive` | no | Key name |
| `--ttl` | `-t` | `int` | no | `control` | no | Time to live in seconds (0 = no expiration) |
| `--value` | `-v` | `string` | yes | `control` | no | Value to store |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr data search`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--filter` | - | `string[]` | no | `control` | no | Filter expression (field==value, field>=value, etc). Repeatable. |
| `--hash-field` | - | `string[]` | no | `control` | no | Field names to use hash equality index (repeatable) |
| `--json` | - | `bool` | no | `control` | no | Output results as JSON |
| `--limit` | - | `int` | no | `control` | no | Maximum results |
| `--prefix` | - | `string` | no | `control` | no | Key prefix namespace to search within |
| `--text` | - | `string` | no | `control` | no | Full-text search query |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr data`

```bash
secretr data
```

### `secretr data delete`

```bash
secretr data delete --key=demo
```

### `secretr data exists`

```bash
secretr data exists --key=demo
```

### `secretr data get`

```bash
secretr data get --key=demo
```

### `secretr data index`

```bash
secretr data index --key=demo --value=demo
```

### `secretr data list`

```bash
secretr data list
```

### `secretr data put`

```bash
secretr data put --key=demo --value=demo
```

### `secretr data search`

```bash
secretr data search
```

## 6. Audit and Observability

All commands in this group are currently observable through:
- CLI command audit events (`type=cli`, `action=command_execute`)
- centralized authz decision events (`type=authz`)
- API request audit events when equivalent API routes are used (`type=api`, `action=request`)

Command-specific domain events may also be emitted by the underlying managers. Validate this explicitly during parity testing.

## 7. Review Checklist (Implementation + Security)

Use this checklist to identify missing implementation pieces and hardening work:

1. Verify every subcommand has expected domain-level audit events (not only CLI/authz wrappers).
2. Validate flag-level ACL behavior for resource-selector flags (especially `--id`, `--name`, `--path`, `--resource`).
3. Confirm positional arguments are explicitly modeled where needed (avoid implicit wildcard behavior).
4. Confirm entitlement scope coverage for all subcommands and critical flags.
5. Add API parity routes/tests for this group if missing.
6. Ensure sensitive outputs are masked by default and require explicit reveal flags.
7. Ensure destructive operations are audited with before/after context and denial reasons.

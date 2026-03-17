# IDENTITY Command Deep-Dive

This document is implementation-oriented guidance for the `secretr identity` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr identity` | Identity management |
| `secretr identity create` | Create a new identity |
| `secretr identity get` | Get identity details |
| `secretr identity list` | List identities |
| `secretr identity recover` | Start identity recovery workflow |
| `secretr identity revoke` | Revoke an identity |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr identity` | `identity:read` |
| `secretr identity create` | `identity:create` |
| `secretr identity get` | `identity:read` |
| `secretr identity list` | `identity:read` |
| `secretr identity recover` | `identity:recover` |
| `secretr identity revoke` | `identity:delete` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr identity` | `identity` | yes |
| `secretr identity create` | `identity` | yes |
| `secretr identity get` | `identity` | yes |
| `secretr identity list` | `identity` | yes |
| `secretr identity recover` | `identity` | yes |
| `secretr identity revoke` | `identity` | yes |

## 4. Flags and Positional Arguments

### `secretr identity`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr identity create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--email` | `-e` | `string` | yes | `control` | no | Email address |
| `--name` | `-n` | `string` | yes | `resource_selector` | yes | Identity name |
| `--password` | `-p` | `string` | no | `sensitive` | no | Password (will prompt if not provided) |
| `--scopes` | `-s` | `string[]` | no | `control` | no | Permission scopes |
| `--type` | `-t` | `string` | no | `control` | no | Identity type: human, service |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr identity get`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Identity ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr identity list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--status` | - | `string` | no | `control` | no | Filter by status |
| `--type` | - | `string` | no | `control` | no | Filter by type |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr identity recover`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--email` | - | `string` | yes | `control` | no | Email address |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr identity revoke`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--force` | - | `bool` | no | `control` | no | Force revocation without confirmation |
| `--id` | - | `string` | yes | `resource_selector` | yes | Identity ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr identity`

```bash
secretr identity
```

### `secretr identity create`

```bash
secretr identity create --email=admin@example.com --name=demo-name
```

### `secretr identity get`

```bash
secretr identity get --id=demo-id
```

### `secretr identity list`

```bash
secretr identity list
```

### `secretr identity recover`

```bash
secretr identity recover --email=admin@example.com
```

### `secretr identity revoke`

```bash
secretr identity revoke --id=demo-id
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

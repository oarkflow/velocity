# ALERT Command Deep-Dive

This document is implementation-oriented guidance for the `secretr alert` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr alert` | Alert management |
| `secretr alert ack` | Acknowledge an alert |
| `secretr alert list` | List alerts |
| `secretr alert resolve` | Resolve an alert |
| `secretr alert rules` | List alert rules |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr alert` | `audit:read` |
| `secretr alert ack` | `audit:read` |
| `secretr alert list` | `audit:read` |
| `secretr alert resolve` | `audit:read` |
| `secretr alert rules` | `audit:read` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr alert` | `-` | no |
| `secretr alert ack` | `-` | no |
| `secretr alert list` | `-` | no |
| `secretr alert resolve` | `-` | no |
| `secretr alert rules` | `-` | no |

## 4. Flags and Positional Arguments

### `secretr alert`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr alert ack`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Alert ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr alert list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--severity` | - | `string` | no | `control` | no | Filter by severity |
| `--status` | - | `string` | no | `control` | no | Filter by status (open, acknowledged, resolved) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr alert resolve`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Alert ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr alert rules`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr alert`

```bash
secretr alert
```

### `secretr alert ack`

```bash
secretr alert ack --id=demo-id
```

### `secretr alert list`

```bash
secretr alert list
```

### `secretr alert resolve`

```bash
secretr alert resolve --id=demo-id
```

### `secretr alert rules`

```bash
secretr alert rules
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

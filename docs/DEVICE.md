# DEVICE Command Deep-Dive

This document is implementation-oriented guidance for the `secretr device` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr device` | Device management |
| `secretr device enroll` | Enroll this device |
| `secretr device list` | List enrolled devices |
| `secretr device revoke` | Revoke a device |
| `secretr device trust` | View device trust score |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr device` | `device:read` |
| `secretr device enroll` | `device:enroll` |
| `secretr device list` | `device:read` |
| `secretr device revoke` | `device:revoke` |
| `secretr device trust` | `device:trust` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr device` | `device` | yes |
| `secretr device enroll` | `device` | yes |
| `secretr device list` | `device` | yes |
| `secretr device revoke` | `device` | yes |
| `secretr device trust` | `device` | yes |

## 4. Flags and Positional Arguments

### `secretr device`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr device enroll`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--name` | `-n` | `string` | yes | `resource_selector` | yes | Device name |
| `--type` | - | `string` | no | `control` | no | Device type: desktop, mobile, server |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr device list`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr device revoke`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Device ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr device trust`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | no | `resource_selector` | yes | Device ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr device`

```bash
secretr device
```

### `secretr device enroll`

```bash
secretr device enroll --name=demo-name
```

### `secretr device list`

```bash
secretr device list
```

### `secretr device revoke`

```bash
secretr device revoke --id=demo-id
```

### `secretr device trust`

```bash
secretr device trust
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

# ADMIN Command Deep-Dive

This document is implementation-oriented guidance for the `secretr admin` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr admin` | Administrative operations |
| `secretr admin security` | Global security settings |
| `secretr admin server` | Start the API server |
| `secretr admin system` | System status and health |
| `secretr admin users` | User administration |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr admin` | `admin:system` |
| `secretr admin security` | `admin:security` |
| `secretr admin server` | `admin:system` |
| `secretr admin system` | `admin:system` |
| `secretr admin users` | `admin:users` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr admin` | `admin` | no |
| `secretr admin security` | `admin` | no |
| `secretr admin server` | `admin` | no |
| `secretr admin system` | `admin` | no |
| `secretr admin users` | `admin` | no |

## 4. Flags and Positional Arguments

### `secretr admin`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr admin security`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr admin server`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--addr` | - | `string` | no | `control` | no | Listen address |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr admin system`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr admin users`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr admin`

```bash
secretr admin
```

### `secretr admin security`

```bash
secretr admin security
```

### `secretr admin server`

```bash
secretr admin server
```

### `secretr admin system`

```bash
secretr admin system
```

### `secretr admin users`

```bash
secretr admin users
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

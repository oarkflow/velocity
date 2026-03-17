# MONITORING Command Deep-Dive

This document is implementation-oriented guidance for the `secretr monitoring` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr monitoring` | System monitoring and behavior analysis |
| `secretr monitoring dashboard` | Show monitoring dashboard |
| `secretr monitoring events` | Query monitoring events |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr monitoring` | `audit:read` |
| `secretr monitoring dashboard` | `audit:read` |
| `secretr monitoring events` | `audit:read` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr monitoring` | `audit` | yes |
| `secretr monitoring dashboard` | `audit` | yes |
| `secretr monitoring events` | `audit` | yes |

## 4. Flags and Positional Arguments

### `secretr monitoring`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr monitoring dashboard`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--period` | - | `string` | no | `control` | no | Time period (1h, 24h, 7d, 30d) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr monitoring events`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--actor` | - | `string` | no | `control` | no | Filter by actor ID |
| `--limit` | - | `int` | no | `control` | no | Max events to show |
| `--type` | - | `string` | no | `control` | no | Filter by event type |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr monitoring`

```bash
secretr monitoring
```

### `secretr monitoring dashboard`

```bash
secretr monitoring dashboard
```

### `secretr monitoring events`

```bash
secretr monitoring events
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

# PIPELINE Command Deep-Dive

This document is implementation-oriented guidance for the `secretr pipeline` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr pipeline` | Manage automation pipelines |
| `secretr pipeline apply` | Apply a pipeline configuration |
| `secretr pipeline list` | List automation pipelines |
| `secretr pipeline trigger` | Trigger an automation event |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr pipeline` | `pipeline:create` |
| `secretr pipeline apply` | `pipeline:create` |
| `secretr pipeline list` | `pipeline:create` |
| `secretr pipeline trigger` | `pipeline:create` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr pipeline` | `pipeline` | yes |
| `secretr pipeline apply` | `pipeline` | yes |
| `secretr pipeline list` | `pipeline` | yes |
| `secretr pipeline trigger` | `pipeline` | yes |

## 4. Flags and Positional Arguments

### `secretr pipeline`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr pipeline apply`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--file` | `-f` | `string` | yes | `resource_selector` | yes | JSON configuration file |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr pipeline list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr pipeline trigger`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--event` | `-e` | `string` | yes | `control` | no | Event name |
| `--param` | `-p` | `string[]` | no | `control` | no | Parameter (key=value) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr pipeline`

```bash
secretr pipeline
```

### `secretr pipeline apply`

```bash
secretr pipeline apply --file=/tmp/input.json
```

### `secretr pipeline list`

```bash
secretr pipeline list
```

### `secretr pipeline trigger`

```bash
secretr pipeline trigger --event=demo
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

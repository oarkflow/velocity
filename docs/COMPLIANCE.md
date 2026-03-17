# COMPLIANCE Command Deep-Dive

This document is implementation-oriented guidance for the `secretr compliance` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr compliance` | Compliance reporting and policy enforcement |
| `secretr compliance frameworks` | List available compliance frameworks |
| `secretr compliance list-reports` | List generated compliance reports |
| `secretr compliance policy` | Manage compliance policies |
| `secretr compliance policy create` | Create policy |
| `secretr compliance policy list` | List policies |
| `secretr compliance policy update` | Update policy |
| `secretr compliance report` | Generate compliance report |
| `secretr compliance score` | Get compliance score |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr compliance` | `compliance:report` |
| `secretr compliance frameworks` | `compliance:report` |
| `secretr compliance list-reports` | `compliance:report` |
| `secretr compliance policy` | `compliance:policy` |
| `secretr compliance policy create` | `compliance:policy` |
| `secretr compliance policy list` | `compliance:policy` |
| `secretr compliance policy update` | `compliance:policy` |
| `secretr compliance report` | `compliance:report` |
| `secretr compliance score` | `compliance:report` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr compliance` | `compliance` | yes |
| `secretr compliance frameworks` | `compliance` | yes |
| `secretr compliance list-reports` | `compliance` | yes |
| `secretr compliance policy` | `compliance` | yes |
| `secretr compliance policy create` | `compliance` | yes |
| `secretr compliance policy list` | `compliance` | yes |
| `secretr compliance policy update` | `compliance` | yes |
| `secretr compliance report` | `compliance` | yes |
| `secretr compliance score` | `compliance` | yes |

## 4. Flags and Positional Arguments

### `secretr compliance`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance frameworks`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance list-reports`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance policy`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance policy create`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance policy list`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance policy update`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance report`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--output` | `-o` | `string` | yes | `control` | no | Output file |
| `--standard` | - | `string` | yes | `control` | no | Compliance standard (e.g., SOC2, GDPR) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr compliance score`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--standard` | - | `string` | yes | `control` | no | Compliance standard |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr compliance`

```bash
secretr compliance
```

### `secretr compliance frameworks`

```bash
secretr compliance frameworks
```

### `secretr compliance list-reports`

```bash
secretr compliance list-reports
```

### `secretr compliance policy`

```bash
secretr compliance policy
```

### `secretr compliance policy create`

```bash
secretr compliance policy create
```

### `secretr compliance policy list`

```bash
secretr compliance policy list
```

### `secretr compliance policy update`

```bash
secretr compliance policy update
```

### `secretr compliance report`

```bash
secretr compliance report --output=/tmp/output.json --standard=demo
```

### `secretr compliance score`

```bash
secretr compliance score --standard=demo
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

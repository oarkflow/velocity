# DLP Command Deep-Dive

This document is implementation-oriented guidance for the `secretr dlp` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr dlp` | Data Loss Prevention |
| `secretr dlp rules` | Manage DLP rules |
| `secretr dlp rules create` | Create rule |
| `secretr dlp rules delete` | Delete rule |
| `secretr dlp rules list` | List rules |
| `secretr dlp scan` | Scan for sensitive data |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr dlp` | `dlp:scan` |
| `secretr dlp rules` | `dlp:rules` |
| `secretr dlp rules create` | `dlp:rules` |
| `secretr dlp rules delete` | `dlp:rules` |
| `secretr dlp rules list` | `dlp:rules` |
| `secretr dlp scan` | `dlp:scan` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr dlp` | `dlp` | yes |
| `secretr dlp rules` | `dlp` | yes |
| `secretr dlp rules create` | `dlp` | yes |
| `secretr dlp rules delete` | `dlp` | yes |
| `secretr dlp rules list` | `dlp` | yes |
| `secretr dlp scan` | `dlp` | yes |

## 4. Flags and Positional Arguments

### `secretr dlp`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr dlp rules`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr dlp rules create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--description` | - | `string` | no | `control` | no | Rule description |
| `--name` | - | `string` | yes | `resource_selector` | yes | Rule name |
| `--patterns` | - | `string[]` | yes | `control` | no | Regex patterns to match |
| `--severity` | - | `string` | no | `control` | no | Severity: critical, high, medium, low |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr dlp rules delete`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Rule ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr dlp rules list`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr dlp scan`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--path` | - | `string` | yes | `resource_selector` | yes | Path to scan |
| `--rules` | - | `string[]` | no | `control` | no | DLP rules to apply |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr dlp`

```bash
secretr dlp
```

### `secretr dlp rules`

```bash
secretr dlp rules
```

### `secretr dlp rules create`

```bash
secretr dlp rules create --name=demo-name --patterns=item1
```

### `secretr dlp rules delete`

```bash
secretr dlp rules delete --id=demo-id
```

### `secretr dlp rules list`

```bash
secretr dlp rules list
```

### `secretr dlp scan`

```bash
secretr dlp scan --path=/tmp/path
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

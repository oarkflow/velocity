# AUTH Command Deep-Dive

This document is implementation-oriented guidance for the `secretr auth` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr auth` | Authentication and session management |
| `secretr auth init` | Initialize system (create first admin) |
| `secretr auth login` | Authenticate and create a session |
| `secretr auth logout` | End current session |
| `secretr auth mfa` | Verify MFA for current session |
| `secretr auth rotate-token` | Rotate the current session token |
| `secretr auth status` | Show current session status |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr auth` | - |
| `secretr auth init` | - |
| `secretr auth login` | - |
| `secretr auth logout` | `auth:logout` |
| `secretr auth mfa` | - |
| `secretr auth rotate-token` | `auth:rotate` |
| `secretr auth status` | `auth:login` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr auth` | `-` | no |
| `secretr auth init` | `-` | no |
| `secretr auth login` | `-` | no |
| `secretr auth logout` | `-` | no |
| `secretr auth mfa` | `-` | no |
| `secretr auth rotate-token` | `-` | no |
| `secretr auth status` | `-` | no |

## 4. Flags and Positional Arguments

### `secretr auth`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth init`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--device-id` | - | `string` | no | `resource_selector` | yes | Initial Device ID |
| `--email` | - | `string` | no | `control` | no | Admin email |
| `--full-name` | - | `string` | no | `resource_selector` | yes | Admin full name |
| `--idle-timeout` | - | `string` | no | `resource_selector` | yes | Session idle timeout (e.g., 24h, 30m) |
| `--name` | - | `string` | no | `resource_selector` | yes | Admin name |
| `--password` | - | `string` | no | `sensitive` | no | Admin Password |
| `--username` | `-u` | `string` | no | `resource_selector` | yes | Admin username (compat) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth login`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--device-id` | - | `string` | no | `resource_selector` | yes | Device ID |
| `--email` | `-e` | `string` | no | `control` | no | Email address |
| `--mfa-token` | - | `string` | no | `sensitive` | no | MFA token |
| `--offline` | - | `bool` | no | `control` | no | Create offline-capable session |
| `--password` | `-p` | `string` | no | `sensitive` | no | Password (will prompt if not provided) |
| `--username` | `-u` | `string` | no | `resource_selector` | yes | Username (compat) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth logout`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth mfa`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--token` | `-t` | `string` | yes | `sensitive` | no | MFA token |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth rotate-token`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr auth status`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr auth`

```bash
secretr auth
```

### `secretr auth init`

```bash
secretr auth init
```

### `secretr auth login`

```bash
secretr auth login
```

### `secretr auth logout`

```bash
secretr auth logout
```

### `secretr auth mfa`

```bash
secretr auth mfa --token=sample-token
```

### `secretr auth rotate-token`

```bash
secretr auth rotate-token
```

### `secretr auth status`

```bash
secretr auth status
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

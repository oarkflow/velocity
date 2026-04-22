# SSH Command Deep-Dive

This document is implementation-oriented guidance for the `secretr ssh` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr ssh` | SSH profile and session management |
| `secretr ssh create-profile` | Create an SSH profile |
| `secretr ssh list-profiles` | List SSH profiles |
| `secretr ssh start` | Start SSH session |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr ssh` | `ssh:manage` |
| `secretr ssh create-profile` | `ssh:manage` |
| `secretr ssh list-profiles` | `ssh:manage` |
| `secretr ssh start` | `ssh:manage` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr ssh` | `ssh` | yes |
| `secretr ssh create-profile` | `ssh` | yes |
| `secretr ssh list-profiles` | `ssh` | yes |
| `secretr ssh start` | `ssh` | yes |

## 4. Flags and Positional Arguments

### `secretr ssh`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr ssh create-profile`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--host` | - | `string` | yes | `control` | no | Host address |
| `--key-id` | - | `string` | yes | `sensitive` | no | Identity Key ID |
| `--name` | - | `string` | yes | `resource_selector` | yes | Profile name |
| `--user` | - | `string` | yes | `control` | no | Username |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr ssh list-profiles`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr ssh start`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--profile-id` | - | `string` | yes | `resource_selector` | yes | Profile ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr ssh`

```bash
secretr ssh
```

### `secretr ssh create-profile`

```bash
secretr ssh create-profile --host=demo --key-id=demo-id --name=demo-name --user=demo
```

### `secretr ssh list-profiles`

```bash
secretr ssh list-profiles
```

### `secretr ssh start`

```bash
secretr ssh start --profile-id=demo-id
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

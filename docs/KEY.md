# KEY Command Deep-Dive

This document is implementation-oriented guidance for the `secretr key` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr key` | Cryptographic key management |
| `secretr key destroy` | Destroy a key with proof |
| `secretr key export` | Export a key for backup |
| `secretr key generate` | Generate a new key |
| `secretr key import` | Import a key from backup |
| `secretr key list` | List keys |
| `secretr key rotate` | Rotate a key |
| `secretr key split` | Split key for M-of-N recovery |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr key` | `key:read` |
| `secretr key destroy` | `key:destroy` |
| `secretr key export` | `key:export` |
| `secretr key generate` | `key:generate` |
| `secretr key import` | `key:import` |
| `secretr key list` | `key:read` |
| `secretr key rotate` | `key:rotate` |
| `secretr key split` | `key:read` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr key` | `key` | yes |
| `secretr key destroy` | `key` | yes |
| `secretr key export` | `key` | yes |
| `secretr key generate` | `key` | yes |
| `secretr key import` | `key` | yes |
| `secretr key list` | `key` | yes |
| `secretr key rotate` | `key` | yes |
| `secretr key split` | `key` | yes |

## 4. Flags and Positional Arguments

### `secretr key`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key destroy`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--force` | - | `bool` | no | `control` | no | Force destruction without confirmation |
| `--id` | - | `string` | yes | `resource_selector` | yes | Key ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key export`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Key ID |
| `--output` | `-o` | `string` | yes | `control` | no | Output file |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key generate`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--expires-in` | - | `duration` | no | `control` | no | Key expiration duration |
| `--purpose` | - | `string` | no | `control` | no | Key purpose |
| `--type` | - | `string` | no | `control` | no | Key type: encryption, signing |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key import`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--input` | `-i` | `string` | yes | `control` | no | Input file |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--status` | - | `string` | no | `control` | no | Filter by status |
| `--type` | - | `string` | no | `control` | no | Filter by type |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key rotate`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Key ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr key split`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Key ID |
| `--shares` | `-n` | `int` | no | `control` | no | Total shares |
| `--threshold` | `-t` | `int` | no | `control` | no | Required threshold |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr key`

```bash
secretr key
```

### `secretr key destroy`

```bash
secretr key destroy --id=demo-id
```

### `secretr key export`

```bash
secretr key export --id=demo-id --output=/tmp/output.json
```

### `secretr key generate`

```bash
secretr key generate
```

### `secretr key import`

```bash
secretr key import --input=/tmp/input.json
```

### `secretr key list`

```bash
secretr key list
```

### `secretr key rotate`

```bash
secretr key rotate --id=demo-id
```

### `secretr key split`

```bash
secretr key split --id=demo-id
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

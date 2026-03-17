# BACKUP Command Deep-Dive

This document is implementation-oriented guidance for the `secretr backup` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr backup` | Backup and restore database contents |
| `secretr backup audit` | View backup/restore audit trail with chain verification |
| `secretr backup create` | Create a backup of secrets, folders, and objects |
| `secretr backup list` | List available backup files in a directory |
| `secretr backup restore` | Restore database from a backup file |
| `secretr backup schedule` | Schedule automated backups |
| `secretr backup verify` | Verify cryptographic signature and integrity of backup file |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr backup` | `backup:create` |
| `secretr backup audit` | `backup:create` |
| `secretr backup create` | `backup:create` |
| `secretr backup list` | `backup:create` |
| `secretr backup restore` | `backup:restore` |
| `secretr backup schedule` | `backup:schedule` |
| `secretr backup verify` | `backup:verify` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr backup` | `backup` | yes |
| `secretr backup audit` | `backup` | yes |
| `secretr backup create` | `backup` | yes |
| `secretr backup list` | `backup` | yes |
| `secretr backup restore` | `backup` | yes |
| `secretr backup schedule` | `backup` | yes |
| `secretr backup verify` | `backup` | yes |

## 4. Flags and Positional Arguments

### `secretr backup`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup audit`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--end` | `-e` | `string` | no | `control` | no | End date (YYYY-MM-DD) |
| `--export` | `-x` | `string` | no | `control` | no | Export audit trail to file |
| `--operation` | `-op` | `string` | no | `control` | no | Filter by operation: backup, restore, export, import |
| `--start` | `-s` | `string` | no | `control` | no | Start date (YYYY-MM-DD) |
| `--verify-chain` | `-v` | `bool` | no | `control` | no | Verify audit chain integrity |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--compress` | `-z` | `bool` | no | `control` | no | Compress the backup with gzip |
| `--description` | `-d` | `string` | no | `control` | no | Backup description |
| `--encrypt` | `-e` | `bool` | no | `control` | no | Encrypt the backup |
| `--filter` | `-f` | `string` | no | `control` | no | Path prefix filter (only backup items matching prefix) |
| `--include` | `-i` | `string[]` | no | `control` | no | Item types to include: secrets, folders, objects (default: all) |
| `--output` | `-o` | `string` | yes | `control` | no | Output backup file path |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--directory` | `-d` | `string` | no | `control` | no | Directory containing backups |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup restore`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--filter` | `-f` | `string` | no | `control` | no | Path prefix filter (only restore items matching prefix) |
| `--include` | `-t` | `string[]` | no | `control` | no | Item types to restore: secrets, folders, objects (default: all) |
| `--input` | `-i` | `string` | yes | `control` | no | Input backup file path |
| `--overwrite` | `-w` | `bool` | no | `control` | no | Overwrite existing items |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup schedule`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--cron` | - | `string` | yes | `control` | no | Cron expression |
| `--destination` | - | `string` | no | `control` | no | Backup destination |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr backup verify`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--input` | `-i` | `string` | yes | `control` | no | Backup file to verify |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr backup`

```bash
secretr backup
```

### `secretr backup audit`

```bash
secretr backup audit
```

### `secretr backup create`

```bash
secretr backup create --output=/tmp/output.json
```

### `secretr backup list`

```bash
secretr backup list
```

### `secretr backup restore`

```bash
secretr backup restore --input=/tmp/input.json
```

### `secretr backup schedule`

```bash
secretr backup schedule --cron=0 2 * * *
```

### `secretr backup verify`

```bash
secretr backup verify --input=/tmp/input.json
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

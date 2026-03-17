# EXPORT Command Deep-Dive

This document is implementation-oriented guidance for the `secretr export` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr export` | Export secrets, folders, and objects to various formats |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr export` | `file:list` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr export` | `file` | yes |

## 4. Flags and Positional Arguments

### `secretr export`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--compress` | `-z` | `bool` | no | `control` | no | Compress output |
| `--format` | `-f` | `string` | no | `output` | no | Export format: json, encrypted-json, tar, tar.gz |
| `--output` | `-o` | `string` | yes | `control` | no | Output file path |
| `--path` | `-p` | `string[]` | yes | `resource_selector` | yes | Item path(s) to export |
| `--pretty` | `-P` | `bool` | no | `control` | no | Pretty print JSON output |
| `--recursive` | `-r` | `bool` | no | `control` | no | For folders: recursively export all contents |
| `--type` | `-t` | `string` | yes | `control` | no | Item type: secret, folder, object |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr export`

```bash
secretr export --output=/tmp/output.json --path=/tmp/path --type=demo
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

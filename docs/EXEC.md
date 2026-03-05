# EXEC Command Deep-Dive

This document is implementation-oriented guidance for the `secretr exec` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr exec` | Execute command with secrets |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr exec` | `exec:run` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr exec` | `-` | no |

## 4. Flags and Positional Arguments

### `secretr exec`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--all-secrets` | - | `bool` | no | `sensitive` | no | Load all secrets as environment variables |
| `--command` | - | `string` | yes | `control` | no | Command to run |
| `--env` | - | `string` | no | `control` | no | Filter bulk-loaded secrets by environment |
| `--env-prefix` | - | `string` | no | `control` | no | Prefix applied to generated environment variable names |
| `--isolation` | - | `string` | no | `control` | no | Isolation level: auto (default), host, ns (Linux namespaces) |
| `--prefix` | - | `string` | no | `control` | no | Load only secrets under prefix/folder as environment variables |
| `--seccomp-profile` | - | `string` | no | `control` | no | Linux seccomp profile (e.g. strict); strict mode fails closed if unavailable |
| `--secret` | `-s` | `string[]` | no | `sensitive` | no | Secret mapping ID:ENV_VAR or ID:ENV_VAR:file |
| `--strict-sandbox` | - | `bool` | no | `control` | no | Fail command if requested sandbox controls are unavailable |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr exec`

```bash
secretr exec --command=go
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

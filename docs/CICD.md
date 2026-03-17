# CICD Command Deep-Dive

This document is implementation-oriented guidance for the `secretr cicd` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr cicd` | CI/CD pipeline integration |
| `secretr cicd create-pipeline` | Register a pipeline identity |
| `secretr cicd inject` | Inject secrets into environment |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr cicd` | `pipeline:create` |
| `secretr cicd create-pipeline` | `pipeline:create` |
| `secretr cicd inject` | `pipeline:inject` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr cicd` | `-` | no |
| `secretr cicd create-pipeline` | `-` | no |
| `secretr cicd inject` | `-` | no |

## 4. Flags and Positional Arguments

### `secretr cicd`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr cicd create-pipeline`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--name` | - | `string` | yes | `resource_selector` | yes | Pipeline name |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--provider` | - | `string` | yes | `resource_selector` | yes | Provider (github, gitlab, etc) |
| `--repo` | - | `string` | yes | `control` | no | Repository identifier |
| `--secret-patterns` | - | `string[]` | no | `sensitive` | no | Secret patterns (e.g., prod/*) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr cicd inject`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--branch` | - | `string` | no | `control` | no | Git branch |
| `--env` | - | `string` | yes | `control` | no | Environment name |
| `--pipeline-id` | - | `string` | yes | `resource_selector` | yes | Pipeline ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr cicd`

```bash
secretr cicd
```

### `secretr cicd create-pipeline`

```bash
secretr cicd create-pipeline --name=demo-name --provider=demo-id --repo=owner/repo
```

### `secretr cicd inject`

```bash
secretr cicd inject --env=general --pipeline-id=demo-id
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

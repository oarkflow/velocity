# INCIDENT Command Deep-Dive

This document is implementation-oriented guidance for the `secretr incident` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr incident` | Incident response |
| `secretr incident declare` | Declare a security incident |
| `secretr incident export` | Export incident evidence |
| `secretr incident freeze` | Freeze organization access |
| `secretr incident list` | List security incidents |
| `secretr incident rotate` | Emergency secret rotation |
| `secretr incident timeline` | View incident timeline |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr incident` | `incident:monitor` |
| `secretr incident declare` | `incident:declare` |
| `secretr incident export` | `incident:export` |
| `secretr incident freeze` | `incident:freeze` |
| `secretr incident list` | `incident:monitor` |
| `secretr incident rotate` | `incident:rotate` |
| `secretr incident timeline` | `incident:timeline` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr incident` | `incident` | yes |
| `secretr incident declare` | `incident` | yes |
| `secretr incident export` | `incident` | yes |
| `secretr incident freeze` | `incident` | yes |
| `secretr incident list` | `incident` | yes |
| `secretr incident rotate` | `incident` | yes |
| `secretr incident timeline` | `incident` | yes |

## 4. Flags and Positional Arguments

### `secretr incident`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident declare`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--description` | `-d` | `string` | yes | `control` | no | Description |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--severity` | - | `string` | no | `control` | no | Severity: critical, high, medium, low |
| `--type` | - | `string` | yes | `control` | no | Incident type |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident export`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Incident ID |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--output` | `-o` | `string` | yes | `control` | no | Output file |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident freeze`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--disable` | - | `bool` | no | `control` | no | Disable freeze (unfreeze) |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident rotate`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--all` | - | `bool` | no | `control` | no | Rotate all secrets |
| `--names` | - | `string[]` | no | `resource_selector` | yes | Specific secrets to rotate |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr incident timeline`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Incident ID |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr incident`

```bash
secretr incident
```

### `secretr incident declare`

```bash
secretr incident declare --description=demo --type=demo
```

### `secretr incident export`

```bash
secretr incident export --id=demo-id --output=/tmp/output.json
```

### `secretr incident freeze`

```bash
secretr incident freeze
```

### `secretr incident list`

```bash
secretr incident list
```

### `secretr incident rotate`

```bash
secretr incident rotate
```

### `secretr incident timeline`

```bash
secretr incident timeline --id=demo-id
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

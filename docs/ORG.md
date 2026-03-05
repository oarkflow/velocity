# ORG Command Deep-Dive

This document is implementation-oriented guidance for the `secretr org` command group.

It is generated from the live CLI/authz surface and intended for parity review, security review, and implementation planning.

## 1. Command Surface

| Subcommand | Purpose |
|---|---|
| `secretr org` | Organization management |
| `secretr org create` | Create an organization |
| `secretr org create-vendor` | Create vendor access |
| `secretr org environments` | Environment management |
| `secretr org environments create` | Create environment |
| `secretr org environments list` | List environments |
| `secretr org grant-auditor` | Grant access to external auditor |
| `secretr org invite` | Invite member to organization |
| `secretr org legal-hold` | Enable legal hold mode |
| `secretr org list` | List organizations |
| `secretr org teams` | Team management |
| `secretr org teams create` | Create team |
| `secretr org teams list` | List teams |
| `secretr org transfer` | M&A resource transfer |
| `secretr org transfer approve` | Approve resource transfer |
| `secretr org transfer execute` | Execute approved transfer |
| `secretr org transfer init` | Initiate transfer between organizations |

## 2. RBAC + Entitlement Scope Requirements

Entitlement scope slugs are expected to match RBAC scope literals exactly.

| Subcommand | Required Scopes |
|---|---|
| `secretr org` | `org:read` |
| `secretr org create` | `org:create` |
| `secretr org create-vendor` | `org:read` |
| `secretr org environments` | `org:environments` |
| `secretr org environments create` | `org:environments` |
| `secretr org environments list` | `org:environments` |
| `secretr org grant-auditor` | `org:read` |
| `secretr org invite` | `org:invite` |
| `secretr org legal-hold` | `org:legal_hold`, `admin:*` |
| `secretr org list` | `org:read` |
| `secretr org teams` | `org:teams` |
| `secretr org teams create` | `org:teams` |
| `secretr org teams list` | `org:teams` |
| `secretr org transfer` | `org:read` |
| `secretr org transfer approve` | `org:read` |
| `secretr org transfer execute` | `org:read` |
| `secretr org transfer init` | `org:read` |

## 3. ACL / Resource Model

| Subcommand | Resource Type | ACL Required |
|---|---|---|
| `secretr org` | `org` | yes |
| `secretr org create` | `org` | yes |
| `secretr org create-vendor` | `org` | yes |
| `secretr org environments` | `org` | yes |
| `secretr org environments create` | `org` | yes |
| `secretr org environments list` | `org` | yes |
| `secretr org grant-auditor` | `org` | yes |
| `secretr org invite` | `org` | yes |
| `secretr org legal-hold` | `org` | yes |
| `secretr org list` | `org` | yes |
| `secretr org teams` | `org` | yes |
| `secretr org teams create` | `org` | yes |
| `secretr org teams list` | `org` | yes |
| `secretr org transfer` | `org` | yes |
| `secretr org transfer approve` | `org` | yes |
| `secretr org transfer execute` | `org` | yes |
| `secretr org transfer init` | `org` | yes |

## 4. Flags and Positional Arguments

### `secretr org`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--name` | `-n` | `string` | yes | `resource_selector` | yes | Organization name |
| `--slug` | - | `string` | no | `control` | no | URL-friendly slug |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org create-vendor`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--name` | - | `string` | yes | `resource_selector` | yes | Vendor Name |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--vendor-id` | - | `string` | yes | `resource_selector` | yes | Vendor Identity ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org environments`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org environments create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--description` | - | `string` | no | `control` | no | Environment description |
| `--name` | - | `string` | yes | `resource_selector` | yes | Environment name |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--type` | - | `string` | no | `control` | no | Environment type (e.g., production, staging) |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org environments list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org grant-auditor`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--auditor-id` | - | `string` | yes | `resource_selector` | yes | Auditor Identity ID |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org invite`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--email` | - | `string` | yes | `control` | no | Email address |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |
| `--role` | - | `string` | no | `control` | no | Role to assign |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org legal-hold`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org list`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org teams`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org teams create`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--name` | - | `string` | yes | `resource_selector` | yes | Team name |
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org teams list`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--org-id` | - | `string` | no | `resource_selector` | yes | Organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org transfer`

Flags:

- none

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org transfer approve`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Transfer ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org transfer execute`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--id` | - | `string` | yes | `resource_selector` | yes | Transfer ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

### `secretr org transfer init`

Flags:

| Flag | Aliases | Type | Required | Auth Class | ACL Required | Description |
|---|---|---|---|---|---|---|
| `--source-org` | - | `string` | yes | `resource_selector` | yes | Source organization ID |
| `--target-org` | - | `string` | yes | `resource_selector` | yes | Target organization ID |

Positional arguments:

| Required Positional Args | Optional Positional Args | ArgsUsage Source |
|---|---|---|
| - | - | `-` |

## 5. Copy-Paste Examples

### `secretr org`

```bash
secretr org
```

### `secretr org create`

```bash
secretr org create --name=demo-name
```

### `secretr org create-vendor`

```bash
secretr org create-vendor --name=demo-name --vendor-id=demo-id
```

### `secretr org environments`

```bash
secretr org environments
```

### `secretr org environments create`

```bash
secretr org environments create --name=demo-name
```

### `secretr org environments list`

```bash
secretr org environments list
```

### `secretr org grant-auditor`

```bash
secretr org grant-auditor --auditor-id=demo-id
```

### `secretr org invite`

```bash
secretr org invite --email=admin@example.com
```

### `secretr org legal-hold`

```bash
secretr org legal-hold
```

### `secretr org list`

```bash
secretr org list
```

### `secretr org teams`

```bash
secretr org teams
```

### `secretr org teams create`

```bash
secretr org teams create --name=demo-name
```

### `secretr org teams list`

```bash
secretr org teams list
```

### `secretr org transfer`

```bash
secretr org transfer
```

### `secretr org transfer approve`

```bash
secretr org transfer approve --id=demo-id
```

### `secretr org transfer execute`

```bash
secretr org transfer execute --id=demo-id
```

### `secretr org transfer init`

```bash
secretr org transfer init --source-org=demo --target-org=demo
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

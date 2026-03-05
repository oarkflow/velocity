# Secretr User Guide

Secretr is a secure secrets platform with deny-first authorization (RBAC + Entitlements + ACL), tamper-evident audit logs (hash chain + Merkle ledger), and secure automation surfaces (CLI + API).

This README is the practical user guide. It explains what each command group is for, what inputs it expects, and gives copy-paste examples.

## Contents

- [1. Install and Build](#1-install-and-build)
- [2. First-Time Setup (Copy-Paste)](#2-first-time-setup-copy-paste)
- [3. Core Concepts](#3-core-concepts)
- [4. Command Groups at a Glance](#4-command-groups-at-a-glance)
- [5. Detailed CLI Usage](#5-detailed-cli-usage)
- [6. API Quick Reference](#6-api-quick-reference)
- [7. Troubleshooting](#7-troubleshooting)
- [8. Documentation Index](#8-documentation-index)
- [9. Complete Flag and Positional Argument Matrices (Every Subcommand)](#9-complete-flag-and-positional-argument-matrices-every-subcommand)

## 1. Install and Build

```bash
go install github.com/oarkflow/velocity/cmd/secretr@latest
# or
cd /Users/sujit/Sites/velocity
go build -o secretr ./cmd/secretr
```

### Build Modes

Production (secure default):
```bash
go build -o secretr ./cmd/secretr
```

Dev/debug (explicit tag):
```bash
go build -tags secretr_dev -o secretr-dev ./cmd/secretr
```

Production mode hardening:
- env-based bypasses are disabled (license path override, yes bypass, insecure password env, self-approval override, JWT secret override, insecure OIDC mock, OIDC JWKS env override)
- CLI startup fails closed if audit chain integrity is broken
- `--debug` flag is hidden

## 2. First-Time Setup (Copy-Paste)

### 2.1 Initialize + Login

```bash
secretr auth init --name "Admin" --email "admin@example.com"
secretr auth login --email "admin@example.com"
secretr auth status
```

### 2.2 License for Entitlement Gating

Production default license file path:
```bash
~/.secretr/license.json
```

Dev-tag builds can override path:
```bash
export SECRETR_LICENSE_PATH=/absolute/path/to/license.json
```

### 2.3 Verify Platform Integrity

```bash
secretr audit verify
```

## 3. Core Concepts

### 3.1 Authorization Model

Every operation must pass all layers:
1. Auth/session
2. RBAC scope
3. Entitlement scope grant
4. ACL / policy check

Decision is deny-first.

### 3.2 Secret Naming

- Key model: `secret:<category>:<name>`
- CLI shorthand defaults `--category general`
- Dot notation supports nested JSON field operations

Example:
- `processgate.aws.client_id`
- `processgate.aws.secret`

### 3.3 Vault Path Log

CLI prints vault path each run:
- `secretr: vault path: ...`

## 4. Command Groups at a Glance

Top-level groups:
- `auth`, `identity`, `device`, `session`, `key`
- `secret`, `object`, `folder`
- `access`, `role`, `policy`, `share`
- `backup`, `org`, `pipeline`, `incident`, `envelope`
- `ssh`, `cicd`, `exec`, `env`, `load-env`, `enrich`
- `monitoring`, `alert`, `admin`, `compliance`, `dlp`, `audit`

For exact full surface and every flag table, see:
- `internal/secretr/COMMANDS.md`
- `internal/secretr/API_REFERENCE.md`

## 5. Detailed CLI Usage

### 5.1 `auth`

Purpose: initialize and authenticate identities.

Important flags:
- `auth init`: `--name`, `--email`, `--password` (optional prompt)
- `auth login`: `--email|--username`, `--password`, `--device-id`
- `auth mfa`: `--token`

```bash
secretr auth init --name "Admin" --email "admin@example.com"
secretr auth login --email "admin@example.com"
secretr auth mfa --token 123456
```

### 5.2 `identity`

Purpose: manage human/service identities.

```bash
secretr identity create --name "CI Bot" --email "ci@example.com" --type service --scopes secret:read --scopes secret:list
secretr identity list --format json
secretr identity revoke --id <IDENTITY_ID>
```

### 5.3 `device` and `session`

Purpose: trust device enrollment and active session control.

```bash
secretr device enroll --name "MacBook" --type desktop
secretr device list
secretr session list
secretr session revoke --id <SESSION_ID>
```

### 5.4 `key`

Purpose: encryption/signing key lifecycle.

```bash
secretr key generate --type encryption --purpose encrypt
secretr key list
secretr key rotate --id <KEY_ID>
secretr key destroy --id <KEY_ID> --force
```

### 5.5 `secret`

Purpose: set/get/list/delete/rotate secrets.

### Expected behavior
- default category: `general`
- nested JSON supported via dot notation
- `--ttl` in seconds

```bash
secretr secret set --name "ENCRYPTED_SECRET" --value "hello"
secretr secret set --name "processgate.aws" --value '{"client_id":"id1","secret":"s1"}'
secretr secret get --name "ENCRYPTED_SECRET" --show
secretr secret get --name "processgate.aws.client_id" --show
secretr secret list --format json
```

### 5.6 `object`

Purpose: store encrypted objects by vault path.

Expected inputs:
- `--path`: vault path like `/apps/api/config.json`
- `--file`: local file path
- `--tag`: `key=value` repeatable

```bash
echo '{"service":"api"}' > /tmp/config.json
secretr object put --path /apps/api/config.json --file /tmp/config.json --tag env=prod --tag owner=platform
secretr object info --path /apps/api/config.json
secretr object get --path /apps/api/config.json --output /tmp/config.download.json
```

### 5.7 `folder`

Purpose: folder-level upload/list/info/delete/copy/rename/size.

```bash
mkdir -p /tmp/demo/sub && echo hello > /tmp/demo/sub/a.txt
secretr folder create --path /projects/demo
secretr folder upload --source /tmp/demo --dest /projects/demo --recursive
secretr folder list --parent /projects --recursive
secretr folder size --path /projects/demo --recursive
```

### 5.8 `access`, `role`, `policy`

Purpose: authorization administration.

### `access`
```bash
secretr access grant --grantee <IDENTITY_ID> --resource general:ENCRYPTED_SECRET --type secret --scopes secret:read --expires-in 2h
secretr access list --grantee <IDENTITY_ID>
secretr access revoke --id <GRANT_ID>
```

### `role`
```bash
secretr role create --name readonly --scopes secret:read --scopes secret:list
secretr role assign --role <ROLE_ID> --identity <IDENTITY_ID>
```

### `policy` file schema
Accepted file formats: JSON or YAML.
Expected model:
- `description`
- `type` (`access|rotation|retention|approval|compliance`)
- `rules[]` where each rule has `id`, `effect`, `actions[]`, `resources[]`, optional `conditions`, optional `priority`

Example file:
```json
{
  "description": "Deny prod delete",
  "type": "access",
  "rules": [
    {
      "id": "deny-prod-delete",
      "effect": "deny",
      "actions": ["secret:delete"],
      "resources": ["prod/*"],
      "conditions": {"environment": "production"},
      "priority": 100
    }
  ]
}
```

```bash
secretr policy create --name prod-guard --file /tmp/policy.json
secretr policy bind --policy <POLICY_ID> --resource prod/db_password --type secret
secretr policy simulate --policy <POLICY_ID> --action secret:delete --resource prod/db_password
```

### 5.9 `share`

Purpose: secure sharing for `secret|file|folder|object`.

```bash
secretr share create --type secret --resource general:ENCRYPTED_SECRET --recipient <IDENTITY_ID> --one-time --max-access 1
secretr share create --type object --resource /apps/api/config.json --recipient <IDENTITY_ID>
secretr share list --format json
secretr share accept --id <SHARE_ID>
secretr share export --id <SHARE_ID> --output /tmp/share-package.json
```

### 5.10 `backup`

Purpose: create/verify/restore backups and schedules.

```bash
secretr backup create --output /tmp/system.backup --include secrets --include objects
secretr backup verify --input /tmp/system.backup --id <BACKUP_ID>
secretr backup restore --input /tmp/system.backup --overwrite
secretr backup schedule --cron "0 2 * * *" --destination "/var/backups:30"
```

### 5.11 `org`

Purpose: org, teams, environments, legal hold, transfer workflows.

```bash
secretr org create --name "Acme Corp"
secretr org teams create --org-id <ORG_ID> --name "platform"
secretr org environments create --org-id <ORG_ID> --name production --type production --description "prod env"
secretr org grant-auditor --org-id <ORG_ID> --auditor-id <IDENTITY_ID>
```

### 5.12 `pipeline`

Purpose: apply/list/trigger automation pipelines.

### Expected `pipeline apply --file` JSON model
- `name`, `description`, `trigger`
- `steps[]`: each step has `name`, `type`, `parameters`
- optional `org_id`, `metadata`

Supported step types:
- `secret:create` params: `name`, `value`
- `org:add_member` params: `org_id`, `identity_id`, `role`
- `access:grant` params: `resource_id`, `resource_type`, `identity_id`, `scopes`

Example:
```json
{
  "name": "user-enroll-bootstrap",
  "description": "Provision baseline access",
  "trigger": "user_enrolled",
  "steps": [
    {
      "name": "create bootstrap token",
      "type": "secret:create",
      "parameters": {
        "name": "general:BOOTSTRAP_{{user_id}}",
        "value": "{{generateToken(user_id)}}"
      }
    }
  ]
}
```

```bash
secretr pipeline apply --file /tmp/pipeline.json
secretr pipeline trigger --event user_enrolled --param user_id=<IDENTITY_ID>
```

### 5.13 `incident`

Purpose: incident declaration, freeze, rotate, timeline, export evidence.

```bash
secretr incident declare --org-id <ORG_ID> --type credential_leak --severity critical --description "AWS key exposed"
secretr incident freeze --org-id <ORG_ID>
secretr incident rotate --org-id <ORG_ID> --all
secretr incident timeline --id <INCIDENT_ID> --org-id <ORG_ID>
secretr incident export --id <INCIDENT_ID> --org-id <ORG_ID> --output /tmp/incident-evidence.json
```

### 5.14 `envelope`

Purpose: secure package with custody chain and audited open/verify operations.

```bash
echo "top secret" > /tmp/secret-note.txt
secretr envelope create --recipient <RECIPIENT_ID> --secret API_KEY:abc123 --file /tmp/secret-note.txt --require-mfa --expires-in 24h --output /tmp/incident-envelope.json
secretr envelope verify --file /tmp/incident-envelope.json
secretr envelope open --file /tmp/incident-envelope.json --inspect
secretr envelope open --file /tmp/incident-envelope.json
```

### 5.15 `cicd`

Purpose: create pipeline identities and inject allowed secrets.

```bash
secretr cicd create-pipeline --name webapp-build --provider github --repo myorg/myrepo --secret-patterns general:* --secret-patterns production/*
secretr cicd inject --pipeline-id <PIPELINE_ID> --env production --branch main --format json
```

### 5.16 `exec`, `env`, `load-env`, `enrich`

Purpose: run processes with secrets injected as env vars.

### `exec` behavior
- if no `--secret`, no `--all-secrets`, and no `--prefix`, bulk loads `general`
- `--prefix` loads keys under prefix/folder
- nested JSON is flattened to uppercase underscore env vars

Flatten example:
```json
{"processgate":{"aws":{"client_id":"id1","secret":"s1"}}}
```
becomes:
- `PROCESSGATE_AWS_CLIENT_ID=id1`
- `PROCESSGATE_AWS_SECRET=s1`

```bash
secretr secret set --name ENCRYPTED_SECRET --value hello
secretr exec --command /usr/bin/env | grep ENCRYPTED_SECRET

secretr secret set --name processgate.aws --value '{"client_id":"id1","secret":"s1"}'
secretr exec --command /usr/bin/env --prefix processgate | grep PROCESSGATE_AWS

secretr env ENCRYPTED_SECRET
secretr load-env
secretr enrich go run ./app
```

### 5.17 `monitoring`, `alert`, `compliance`, `dlp`, `audit`, `admin`, `ssh`

### Monitoring and alerts
```bash
secretr monitoring dashboard --period 24h
secretr monitoring events --limit 50
secretr alert list --status open
secretr alert ack --id <ALERT_ID>
secretr alert resolve --id <ALERT_ID>
```

### Compliance
```bash
secretr compliance frameworks
secretr compliance score --standard SOC2 --org-id <ORG_ID>
secretr compliance report --standard SOC2 --output /tmp/soc2-report.json --org-id <ORG_ID>
```

### DLP
```bash
secretr dlp rules create --name aws-key-detection --patterns 'AKIA[0-9A-Z]{16}' --severity high
secretr dlp scan --path /tmp/sample.txt
secretr dlp rules list
```

### Audit
```bash
secretr audit query --limit 20 --format json
secretr audit export --output /tmp/audit-export.json
secretr audit verify
```

### Admin and SSH
```bash
secretr admin users --format json
secretr admin server --addr :9090
secretr ssh list-profiles
```

## 6. API Quick Reference

Base URL:
```bash
export API_BASE="http://127.0.0.1:9090"
export SESSION_ID="<SESSION_ID>"
export AUTHZ_HEADER="Authorization: Bearer ${SESSION_ID}"
```

Common endpoints:
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET|POST|PUT|DELETE /api/v1/secrets...`
- `GET|POST|DELETE /api/v1/files...`
- `GET /api/v1/audit`, `GET /api/v1/audit/export`
- `POST /api/v1/commands/:command_path` (command-dispatch parity surface)

Use detailed API docs for payload schemas:
- `internal/secretr/API_REFERENCE.md`

## 7. Troubleshooting

### `Error [entitlement_scope_required]`
Cause: missing license or missing scope grant.

Fix:
1. place production license at `~/.secretr/license.json`
2. verify scope exists in entitlement `features.<feature>.scopes.<scope_slug>`

### `Error [acl_denied]`
Cause: missing ACL grant or unresolved protected resource id.

Fix:
1. verify resource exists and id/path is correct
2. grant ACL scope/resource access
3. retry with exact `--resource`, `--id`, `--name`, or route path

### `secretr exec` shows empty env
Check:
```bash
secretr secret list --format json
secretr exec --command /usr/bin/env | grep ENCRYPTED_SECRET
secretr exec --command /usr/bin/env --prefix processgate | grep PROCESSGATE_AWS
```

## 8. Documentation Index

- User guide (this file): `internal/secretr/README.md`
- Full CLI command + flags matrix: `internal/secretr/COMMANDS.md`
- Full API endpoint + authz matrix: `internal/secretr/API_REFERENCE.md`
- Logging and audit deep-dive: `internal/secretr/AUDIT.md`
- Envelope implementation deep-dive: `internal/secretr/ENVELOPE.md`
- Per-top-level command deep-dives:
  - `internal/secretr/ACCESS.md`, `AUTH.md`, `IDENTITY.md`, `DEVICE.md`, `SESSION.md`, `KEY.md`, `SECRET.md`
  - `internal/secretr/OBJECT.md`, `FOLDER.md`, `SHARE.md`, `POLICY.md`, `ROLE.md`, `ORG.md`, `PIPELINE.md`, `INCIDENT.md`
  - `internal/secretr/CICD.md`, `EXEC.md`, `ENV.md`, `LOAD_ENV.md`, `ENRICH.md`, `MONITORING.md`, `ALERT.md`
  - `internal/secretr/COMPLIANCE.md`, `DLP.md`, `ADMIN.md`, `SSH.md`, `BACKUP.md`, `DATA.md`, `IMPORT.md`, `EXPORT.md`
## 9. Complete Flag and Positional Argument Matrices (Every Subcommand)

Source: generated from the live CLI command tree.

### access

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr access` | - | - |
| `secretr access approve` | `--id` | - |
| `secretr access grant` | `--grantee (-g)`, `--resource (-r)` | `--expires-in`, `--resharing`, `--scopes (-s)`, `--type` |
| `secretr access list` | - | `--grantee`, `--resource` |
| `secretr access request` | `--duration`, `--justification`, `--resource`, `--type` | - |
| `secretr access revoke` | `--id` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr access` | - | - |
| `secretr access approve` | - | - |
| `secretr access grant` | - | - |
| `secretr access list` | - | - |
| `secretr access request` | - | - |
| `secretr access revoke` | - | - |

### admin

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr admin` | - | - |
| `secretr admin security` | - | - |
| `secretr admin server` | - | `--addr` |
| `secretr admin system` | - | - |
| `secretr admin users` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr admin` | - | - |
| `secretr admin security` | - | - |
| `secretr admin server` | - | - |
| `secretr admin system` | - | - |
| `secretr admin users` | - | - |

### alert

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr alert` | - | - |
| `secretr alert ack` | `--id` | - |
| `secretr alert list` | - | `--severity`, `--status` |
| `secretr alert resolve` | `--id` | - |
| `secretr alert rules` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr alert` | - | - |
| `secretr alert ack` | - | - |
| `secretr alert list` | - | - |
| `secretr alert resolve` | - | - |
| `secretr alert rules` | - | - |

### audit

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr audit` | - | - |
| `secretr audit export` | `--output (-o)` | `--end`, `--start` |
| `secretr audit query` | - | `--action`, `--actor`, `--end`, `--limit`, `--resource`, `--start` |
| `secretr audit verify` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr audit` | - | - |
| `secretr audit export` | - | - |
| `secretr audit query` | - | - |
| `secretr audit verify` | - | - |

### auth

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr auth` | - | - |
| `secretr auth init` | - | `--device-id`, `--email`, `--full-name`, `--idle-timeout`, `--name`, `--password`, `--username (-u)` |
| `secretr auth login` | - | `--device-id`, `--email (-e)`, `--mfa-token`, `--offline`, `--password (-p)`, `--username (-u)` |
| `secretr auth logout` | - | - |
| `secretr auth mfa` | `--token (-t)` | - |
| `secretr auth rotate-token` | - | - |
| `secretr auth status` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr auth` | - | - |
| `secretr auth init` | - | - |
| `secretr auth login` | - | - |
| `secretr auth logout` | - | - |
| `secretr auth mfa` | - | - |
| `secretr auth rotate-token` | - | - |
| `secretr auth status` | - | - |

### backup

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr backup` | - | - |
| `secretr backup audit` | - | `--end (-e)`, `--export (-x)`, `--operation (-op)`, `--start (-s)`, `--verify-chain (-v)` |
| `secretr backup create` | `--output (-o)` | `--compress (-z)`, `--description (-d)`, `--encrypt (-e)`, `--filter (-f)`, `--include (-i)` |
| `secretr backup list` | - | `--directory (-d)` |
| `secretr backup restore` | `--input (-i)` | `--filter (-f)`, `--include (-t)`, `--overwrite (-w)` |
| `secretr backup schedule` | `--cron` | `--destination` |
| `secretr backup verify` | `--input (-i)` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr backup` | - | - |
| `secretr backup audit` | - | - |
| `secretr backup create` | - | - |
| `secretr backup list` | - | - |
| `secretr backup restore` | - | - |
| `secretr backup schedule` | - | - |
| `secretr backup verify` | - | - |

### cicd

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr cicd` | - | - |
| `secretr cicd create-pipeline` | `--name`, `--provider`, `--repo` | `--org-id`, `--secret-patterns` |
| `secretr cicd inject` | `--env`, `--pipeline-id` | `--branch` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr cicd` | - | - |
| `secretr cicd create-pipeline` | - | - |
| `secretr cicd inject` | - | - |

### compliance

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr compliance` | - | - |
| `secretr compliance frameworks` | - | - |
| `secretr compliance list-reports` | - | `--org-id` |
| `secretr compliance policy` | - | - |
| `secretr compliance policy create` | - | - |
| `secretr compliance policy list` | - | - |
| `secretr compliance policy update` | - | - |
| `secretr compliance report` | `--output (-o)`, `--standard` | - |
| `secretr compliance score` | `--standard` | `--org-id` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr compliance` | - | - |
| `secretr compliance frameworks` | - | - |
| `secretr compliance list-reports` | - | - |
| `secretr compliance policy` | - | - |
| `secretr compliance policy create` | - | - |
| `secretr compliance policy list` | - | - |
| `secretr compliance policy update` | - | - |
| `secretr compliance report` | - | - |
| `secretr compliance score` | - | - |

### data

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr data` | - | - |
| `secretr data delete` | `--key (-k)` | - |
| `secretr data exists` | `--key (-k)` | - |
| `secretr data get` | `--key (-k)` | `--json (-j)` |
| `secretr data index` | `--key (-k)`, `--value (-v)` | `--json (-j)`, `--prefix`, `--schema` |
| `secretr data list` | - | `--limit (-l)`, `--offset (-o)`, `--prefix (-p)` |
| `secretr data put` | `--key (-k)`, `--value (-v)` | `--json (-j)`, `--ttl (-t)` |
| `secretr data search` | - | `--filter`, `--hash-field`, `--json`, `--limit`, `--prefix`, `--text` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr data` | - | - |
| `secretr data delete` | - | - |
| `secretr data exists` | - | - |
| `secretr data get` | - | - |
| `secretr data index` | - | - |
| `secretr data list` | - | - |
| `secretr data put` | - | - |
| `secretr data search` | - | - |

### device

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr device` | - | - |
| `secretr device enroll` | `--name (-n)` | `--type` |
| `secretr device list` | - | - |
| `secretr device revoke` | `--id` | - |
| `secretr device trust` | - | `--id` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr device` | - | - |
| `secretr device enroll` | - | - |
| `secretr device list` | - | - |
| `secretr device revoke` | - | - |
| `secretr device trust` | - | - |

### dlp

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr dlp` | - | - |
| `secretr dlp rules` | - | - |
| `secretr dlp rules create` | `--name`, `--patterns` | `--description`, `--severity` |
| `secretr dlp rules delete` | `--id` | - |
| `secretr dlp rules list` | - | - |
| `secretr dlp scan` | `--path` | `--rules` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr dlp` | - | - |
| `secretr dlp rules` | - | - |
| `secretr dlp rules create` | - | - |
| `secretr dlp rules delete` | - | - |
| `secretr dlp rules list` | - | - |
| `secretr dlp scan` | - | - |

### enrich

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr enrich` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr enrich` | - | - |

### env

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr env` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr env` | - | - |

### envelope

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr envelope` | - | - |
| `secretr envelope create` | `--output (-o)`, `--recipient (-r)` | `--expires-in`, `--file (-f)`, `--message (-m)`, `--policy (-p)`, `--require-mfa`, `--secret (-s)` |
| `secretr envelope open` | `--file (-f)` | `--inspect` |
| `secretr envelope verify` | `--file (-f)` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr envelope` | - | - |
| `secretr envelope create` | - | - |
| `secretr envelope open` | - | - |
| `secretr envelope verify` | - | - |

### exec

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr exec` | `--command` | `--all-secrets`, `--env`, `--env-prefix`, `--isolation`, `--prefix`, `--seccomp-profile`, `--secret (-s)`, `--strict-sandbox` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr exec` | - | - |

### export

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr export` | `--output (-o)`, `--path (-p)`, `--type (-t)` | `--compress (-z)`, `--format (-f)`, `--pretty (-P)`, `--recursive (-r)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr export` | - | - |

### folder

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr folder` | - | - |
| `secretr folder copy` | `--dest (-d)`, `--source (-s)` | `--user (-u)` |
| `secretr folder create` | `--path (-p)` | `--paths (-m)`, `--user (-u)` |
| `secretr folder delete` | `--path (-p)` | `--recursive (-r)`, `--user (-u)` |
| `secretr folder info` | `--path (-p)` | - |
| `secretr folder list` | - | `--parent (-p)`, `--recursive (-r)` |
| `secretr folder rename` | `--new (-n)`, `--old (-o)` | `--user (-u)` |
| `secretr folder size` | `--path (-p)` | `--recursive (-r)` |
| `secretr folder upload` | `--dest (-d)`, `--source (-s)` | `--encrypt (-e)`, `--recursive (-r)` |
| `secretr folder view` | `--path (-p)` | `--compress (-c)`, `--max-file-size` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr folder` | - | - |
| `secretr folder copy` | - | - |
| `secretr folder create` | - | - |
| `secretr folder delete` | - | - |
| `secretr folder info` | - | - |
| `secretr folder list` | - | - |
| `secretr folder rename` | - | - |
| `secretr folder size` | - | - |
| `secretr folder upload` | - | - |
| `secretr folder view` | - | - |

### identity

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr identity` | - | - |
| `secretr identity create` | `--email (-e)`, `--name (-n)` | `--password (-p)`, `--scopes (-s)`, `--type (-t)` |
| `secretr identity get` | `--id` | - |
| `secretr identity list` | - | `--status`, `--type` |
| `secretr identity recover` | `--email` | - |
| `secretr identity revoke` | `--id` | `--force` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr identity` | - | - |
| `secretr identity create` | - | - |
| `secretr identity get` | - | - |
| `secretr identity list` | - | - |
| `secretr identity recover` | - | - |
| `secretr identity revoke` | - | - |

### import

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr import` | `--input (-i)` | `--dry-run (-n)`, `--format (-f)`, `--overwrite (-w)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr import` | - | - |

### incident

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr incident` | - | - |
| `secretr incident declare` | `--description (-d)`, `--type` | `--org-id`, `--severity` |
| `secretr incident export` | `--id`, `--output (-o)` | `--org-id` |
| `secretr incident freeze` | - | `--disable`, `--org-id` |
| `secretr incident list` | - | `--org-id` |
| `secretr incident rotate` | - | `--all`, `--names`, `--org-id` |
| `secretr incident timeline` | `--id` | `--org-id` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr incident` | - | - |
| `secretr incident declare` | - | - |
| `secretr incident export` | - | - |
| `secretr incident freeze` | - | - |
| `secretr incident list` | - | - |
| `secretr incident rotate` | - | - |
| `secretr incident timeline` | - | - |

### key

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr key` | - | - |
| `secretr key destroy` | `--id` | `--force` |
| `secretr key export` | `--id`, `--output (-o)` | - |
| `secretr key generate` | - | `--expires-in`, `--purpose`, `--type` |
| `secretr key import` | `--input (-i)` | - |
| `secretr key list` | - | `--status`, `--type` |
| `secretr key rotate` | `--id` | - |
| `secretr key split` | `--id` | `--shares (-n)`, `--threshold (-t)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr key` | - | - |
| `secretr key destroy` | - | - |
| `secretr key export` | - | - |
| `secretr key generate` | - | - |
| `secretr key import` | - | - |
| `secretr key list` | - | - |
| `secretr key rotate` | - | - |
| `secretr key split` | - | - |

### load-env

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr load-env` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr load-env` | - | - |

### monitoring

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr monitoring` | - | - |
| `secretr monitoring dashboard` | - | `--period` |
| `secretr monitoring events` | - | `--actor`, `--limit`, `--type` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr monitoring` | - | - |
| `secretr monitoring dashboard` | - | - |
| `secretr monitoring events` | - | - |

### object

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr object` | - | - |
| `secretr object delete` | `--path (-p)` | `--user (-u)` |
| `secretr object get` | `--output (-o)`, `--path (-p)` | - |
| `secretr object info` | `--path (-p)` | - |
| `secretr object list` | - | `--folder (-f)`, `--limit (-l)`, `--prefix (-p)`, `--recursive (-r)` |
| `secretr object put` | `--file (-f)`, `--path (-p)` | `--content-type (-c)`, `--encrypt (-e)`, `--tag (-t)` |
| `secretr object view` | `--path (-p)` | `--user (-u)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr object` | - | - |
| `secretr object delete` | - | - |
| `secretr object get` | - | - |
| `secretr object info` | - | - |
| `secretr object list` | - | - |
| `secretr object put` | - | - |
| `secretr object view` | - | - |

### org

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr org` | - | - |
| `secretr org create` | `--name (-n)` | `--slug` |
| `secretr org create-vendor` | `--name`, `--vendor-id` | `--org-id` |
| `secretr org environments` | - | - |
| `secretr org environments create` | `--name` | `--description`, `--org-id`, `--type` |
| `secretr org environments list` | - | `--org-id` |
| `secretr org grant-auditor` | `--auditor-id` | `--org-id` |
| `secretr org invite` | `--email` | `--org-id`, `--role` |
| `secretr org legal-hold` | - | `--org-id` |
| `secretr org list` | - | - |
| `secretr org teams` | - | - |
| `secretr org teams create` | `--name` | `--org-id` |
| `secretr org teams list` | - | `--org-id` |
| `secretr org transfer` | - | - |
| `secretr org transfer approve` | `--id` | - |
| `secretr org transfer execute` | `--id` | - |
| `secretr org transfer init` | `--source-org`, `--target-org` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr org` | - | - |
| `secretr org create` | - | - |
| `secretr org create-vendor` | - | - |
| `secretr org environments` | - | - |
| `secretr org environments create` | - | - |
| `secretr org environments list` | - | - |
| `secretr org grant-auditor` | - | - |
| `secretr org invite` | - | - |
| `secretr org legal-hold` | - | - |
| `secretr org list` | - | - |
| `secretr org teams` | - | - |
| `secretr org teams create` | - | - |
| `secretr org teams list` | - | - |
| `secretr org transfer` | - | - |
| `secretr org transfer approve` | - | - |
| `secretr org transfer execute` | - | - |
| `secretr org transfer init` | - | - |

### pipeline

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr pipeline` | - | - |
| `secretr pipeline apply` | `--file (-f)` | - |
| `secretr pipeline list` | - | `--org-id` |
| `secretr pipeline trigger` | `--event (-e)` | `--param (-p)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr pipeline` | - | - |
| `secretr pipeline apply` | - | - |
| `secretr pipeline list` | - | - |
| `secretr pipeline trigger` | - | - |

### policy

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr policy` | - | - |
| `secretr policy bind` | `--policy`, `--resource` | - |
| `secretr policy create` | `--name (-n)` | `--file (-f)` |
| `secretr policy freeze` | - | - |
| `secretr policy list` | - | - |
| `secretr policy simulate` | `--action`, `--policy` | `--resource` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr policy` | - | - |
| `secretr policy bind` | - | - |
| `secretr policy create` | - | - |
| `secretr policy freeze` | - | - |
| `secretr policy list` | - | - |
| `secretr policy simulate` | - | - |

### role

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr role` | - | - |
| `secretr role assign` | `--identity`, `--role` | - |
| `secretr role create` | `--name (-n)` | `--description (-d)`, `--scopes (-s)` |
| `secretr role list` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr role` | - | - |
| `secretr role assign` | - | - |
| `secretr role create` | - | - |
| `secretr role list` | - | - |

### secret

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr secret` | - | - |
| `secretr secret delete` | `--name (-n)` | `--category (-c)` |
| `secretr secret get` | `--name (-n)` | `--category (-c)`, `--show (-s)` |
| `secretr secret list` | - | `--category (-c)` |
| `secretr secret rotate` | `--name (-n)` | `--category (-c)`, `--length (-l)` |
| `secretr secret set` | `--name (-n)`, `--value (-v)` | `--category (-c)`, `--ttl (-t)` |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr secret` | - | - |
| `secretr secret delete` | - | - |
| `secretr secret get` | - | - |
| `secretr secret list` | - | - |
| `secretr secret rotate` | - | - |
| `secretr secret set` | - | - |

### session

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr session` | - | - |
| `secretr session list` | - | - |
| `secretr session revoke` | `--id` | - |
| `secretr session revoke-all` | - | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr session` | - | - |
| `secretr session list` | - | - |
| `secretr session revoke` | - | - |
| `secretr session revoke-all` | - | - |

### share

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr share` | - | - |
| `secretr share accept` | `--id` | - |
| `secretr share create` | `--resource (-r)`, `--type` | `--expires-in`, `--max-access`, `--one-time`, `--recipient` |
| `secretr share export` | `--id`, `--output (-o)` | - |
| `secretr share list` | - | - |
| `secretr share revoke` | `--id` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr share` | - | - |
| `secretr share accept` | - | - |
| `secretr share create` | - | - |
| `secretr share export` | - | - |
| `secretr share list` | - | - |
| `secretr share revoke` | - | - |

### ssh

Flag Matrix

| Subcommand | Required Flags | Optional Flags |
|---|---|---|
| `secretr ssh` | - | - |
| `secretr ssh create-profile` | `--host`, `--key-id`, `--name`, `--user` | - |
| `secretr ssh list-profiles` | - | - |
| `secretr ssh start` | `--profile-id` | - |

Positional Args Matrix

| Subcommand | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr ssh` | - | - |
| `secretr ssh create-profile` | - | - |
| `secretr ssh list-profiles` | - | - |
| `secretr ssh start` | - | - |

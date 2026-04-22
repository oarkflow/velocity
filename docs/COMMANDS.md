# Secretr Command Reference

This file is auto-generated from the live CLI command tree.
Do not edit manually. Regenerate with:

```bash
go run ./internal/secretr/cmd/gendocs
```

## Usage Notes
- Commands are grouped by top-level namespace.
- `Required` flags are mandatory.
- `Minimal Example` is intended to be copy-paste runnable with sample values.
- For environment-specific values (IDs, files, emails), replace sample values as needed.

## access

### secretr access

- **What**: Access control and delegation

Flags: none

Minimal Example:

```bash
secretr access
```

### secretr access approve

- **What**: Approve a JIT access request

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Request ID |

Minimal Example:

```bash
secretr access approve --id=demo-id
```

Full Flags Example:

```bash
secretr access approve --id=demo-id
```

### secretr access grant

- **What**: Grant access to a resource

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--expires-in` | duration | no | `0s` | Grant expiration |
| `--grantee` (`-g`) | string | yes | `-` | Grantee identity ID |
| `--resharing` | bool | no | `false` | Allow grantee to reshare |
| `--resource` (`-r`) | string | yes | `-` | Resource ID |
| `--scopes` (`-s`) | string[] | no | `-` | Scopes to grant |
| `--type` | string | no | `-` | Resource type: secret, file, key |

Minimal Example:

```bash
secretr access grant --grantee=demo --resource=demo
```

Full Flags Example:

```bash
secretr access grant --expires-in=24h --grantee=demo --resource=demo --scopes=item1 --scopes=secret:read --type=demo
```

### secretr access list

- **What**: List access grants

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--grantee` | string | no | `-` | Filter by grantee |
| `--resource` | string | no | `-` | Filter by resource |

Minimal Example:

```bash
secretr access list
```

Full Flags Example:

```bash
secretr access list --grantee=demo --resource=demo
```

### secretr access request

- **What**: Request temporary JIT access

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--duration` | string | yes | `-` | Duration (e.g. 1h, 30m) |
| `--justification` | string | yes | `-` | Justification for access |
| `--resource` | string | yes | `-` | Resource ID |
| `--type` | string | yes | `-` | Resource type |

Minimal Example:

```bash
secretr access request --duration=demo --justification=demo --resource=demo --type=demo
```

Full Flags Example:

```bash
secretr access request --duration=demo --justification=demo --resource=demo --type=demo
```

### secretr access revoke

- **What**: Revoke access

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Grant ID |

Minimal Example:

```bash
secretr access revoke --id=demo-id
```

Full Flags Example:

```bash
secretr access revoke --id=demo-id
```

## admin

### secretr admin

- **What**: Administrative operations

Flags: none

Minimal Example:

```bash
secretr admin
```

### secretr admin server

- **What**: Start the API server

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--addr` | string | no | `:9090` | Listen address |

Minimal Example:

```bash
secretr admin server
```

Full Flags Example:

```bash
secretr admin server --addr=:9090
```

### secretr admin system

- **What**: System status and health

Flags: none

Minimal Example:

```bash
secretr admin system
```

### secretr admin users

- **What**: User administration

Flags: none

Minimal Example:

```bash
secretr admin users
```

## alert

### secretr alert

- **What**: Alert management

Flags: none

Minimal Example:

```bash
secretr alert
```

### secretr alert ack

- **What**: Acknowledge an alert

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Alert ID |

Minimal Example:

```bash
secretr alert ack --id=demo-id
```

Full Flags Example:

```bash
secretr alert ack --id=demo-id
```

### secretr alert list

- **What**: List alerts

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--severity` | string | no | `-` | Filter by severity |
| `--status` | string | no | `-` | Filter by status (open, acknowledged, resolved) |

Minimal Example:

```bash
secretr alert list
```

Full Flags Example:

```bash
secretr alert list --severity=high --status=demo
```

### secretr alert resolve

- **What**: Resolve an alert

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Grant ID |

Minimal Example:

```bash
secretr alert resolve --id=demo-id
```

Full Flags Example:

```bash
secretr alert resolve --id=demo-id
```

### secretr alert rules

- **What**: List alert rules

Flags: none

Minimal Example:

```bash
secretr alert rules
```

## audit

### secretr audit

- **What**: Audit log management

Flags: none

Minimal Example:

```bash
secretr audit
```

### secretr audit export

- **What**: Export signed audit log

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--end` | string | no | `-` | --end time	End time |
| `--output` (`-o`) | string | yes | `-` | Output file |
| `--start` | string | no | `-` | --start time	Start time |

Minimal Example:

```bash
secretr audit export --output=/tmp/output.json
```

Full Flags Example:

```bash
secretr audit export --end=demo --output=/tmp/output.json --start=demo
```

### secretr audit query

- **What**: Query audit log

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--action` | string | no | `-` | Filter by action |
| `--actor` | string | no | `-` | Filter by actor ID |
| `--end` | string | no | `-` | --end time	End time |
| `--limit` | int | no | `100` | Result limit |
| `--resource` | string | no | `-` | Filter by resource ID |
| `--start` | string | no | `-` | --start time	Start time |

Minimal Example:

```bash
secretr audit query
```

Full Flags Example:

```bash
secretr audit query --action=demo --actor=demo --end=demo --limit=20 --resource=demo --start=demo
```

### secretr audit verify

- **What**: Verify audit log integrity

Flags: none

Minimal Example:

```bash
secretr audit verify
```

## auth

### secretr auth

- **What**: Authentication and session management

Flags: none

Minimal Example:

```bash
secretr auth
```

### secretr auth init

- **What**: Initialize system (create first admin)

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--device-id` | string | no | `-` | Initial Device ID |
| `--email` | string | no | `-` | Admin email |
| `--full-name` | string | no | `-` | Admin full name |
| `--idle-timeout` | string | no | `24h` | Session idle timeout (e.g., 24h, 30m) |
| `--name` | string | no | `-` | Admin name |
| `--password` | string | no | `-` | Admin Password |
| `--username` (`-u`) | string | no | `-` | Admin username (compat) |

Minimal Example:

```bash
secretr auth init
```

Full Flags Example:

```bash
secretr auth init --device-id=demo-id --email=admin@example.com --full-name=demo --idle-timeout=demo-id --name=demo-name --password=ChangeMe123! --username=admin
```

### secretr auth login

- **What**: Authenticate and create a session

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--device-id` | string | no | `-` | Device ID |
| `--email` (`-e`) | string | no | `-` | Email address |
| `--mfa-token` | string | no | `-` | MFA token |
| `--offline` | bool | no | `false` | Create offline-capable session |
| `--password` (`-p`) | string | no | `-` | Password (will prompt if not provided) |
| `--username` (`-u`) | string | no | `-` | Username (compat) |

Minimal Example:

```bash
secretr auth login
```

Full Flags Example:

```bash
secretr auth login --device-id=demo-id --email=admin@example.com --mfa-token=dev-token --password=ChangeMe123! --username=admin
```

### secretr auth logout

- **What**: End current session

Flags: none

Minimal Example:

```bash
secretr auth logout
```

### secretr auth mfa

- **What**: Verify MFA for current session

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--token` (`-t`) | string | yes | `-` | MFA token |

Minimal Example:

```bash
secretr auth mfa --token=dev-token
```

Full Flags Example:

```bash
secretr auth mfa --token=dev-token
```

### secretr auth rotate-token

- **What**: Rotate the current session token

Flags: none

Minimal Example:

```bash
secretr auth rotate-token
```

### secretr auth status

- **What**: Show current session status

Flags: none

Minimal Example:

```bash
secretr auth status
```

## backup

### secretr backup

- **What**: Backup and restore database contents
- **Description**: Database backup and restore operations

Flags: none

Minimal Example:

```bash
secretr backup
```

### secretr backup audit

- **What**: View backup/restore audit trail with chain verification
- **Description**: View audit trail

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--end` (`-e`) | string | no | `-` | End date (YYYY-MM-DD) |
| `--export` (`-x`) | string | no | `-` | Export audit trail to file |
| `--operation` (`-op`) | string | no | `-` | Filter by operation: backup, restore, export, import |
| `--start` (`-s`) | string | no | `-` | Start date (YYYY-MM-DD) |
| `--verify-chain` (`-v`) | bool | no | `false` | Verify audit chain integrity |

Minimal Example:

```bash
secretr backup audit
```

Full Flags Example:

```bash
secretr backup audit --end=demo --export=demo --operation=demo --start=demo
```

### secretr backup create

- **What**: Create a backup of secrets, folders, and objects
- **Description**: Create a database backup

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--compress` (`-z`) | bool | no | `true` | Compress the backup with gzip |
| `--description` (`-d`) | string | no | `-` | Backup description |
| `--encrypt` (`-e`) | bool | no | `true` | Encrypt the backup |
| `--filter` (`-f`) | string | no | `-` | Path prefix filter (only backup items matching prefix) |
| `--include` (`-i`) | string[] | no | `-` | Item types to include: secrets, folders, objects (default: all) |
| `--output` (`-o`) | string | yes | `-` | Output backup file path |

Minimal Example:

```bash
secretr backup create --output=/tmp/output.json
```

Full Flags Example:

```bash
secretr backup create --description=demo --filter=demo --include=item1 --include=item2 --output=/tmp/output.json
```

### secretr backup list

- **What**: List available backup files in a directory
- **Description**: List backup files

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--directory` (`-d`) | string | no | `./backups` | Directory containing backups |

Minimal Example:

```bash
secretr backup list
```

Full Flags Example:

```bash
secretr backup list --directory=demo
```

### secretr backup restore

- **What**: Restore database from a backup file
- **Description**: Restore from a backup

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--filter` (`-f`) | string | no | `-` | Path prefix filter (only restore items matching prefix) |
| `--include` (`-t`) | string[] | no | `-` | Item types to restore: secrets, folders, objects (default: all) |
| `--input` (`-i`) | string | yes | `-` | Input backup file path |
| `--overwrite` (`-w`) | bool | no | `false` | Overwrite existing items |

Minimal Example:

```bash
secretr backup restore --input=/tmp/input.json
```

Full Flags Example:

```bash
secretr backup restore --filter=demo --include=item1 --include=item2 --input=/tmp/input.json
```

### secretr backup schedule

- **What**: Schedule automated backups

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--cron` | string | yes | `-` | Cron expression |
| `--destination` | string | no | `-` | Backup destination |

Minimal Example:

```bash
secretr backup schedule --cron=0 2 * * *
```

Full Flags Example:

```bash
secretr backup schedule --cron=0 2 * * * --destination=demo
```

### secretr backup verify

- **What**: Verify cryptographic signature and integrity of backup file
- **Description**: Verify backup integrity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--input` (`-i`) | string | yes | `-` | Backup file to verify |

Minimal Example:

```bash
secretr backup verify --input=/tmp/input.json
```

Full Flags Example:

```bash
secretr backup verify --input=/tmp/input.json
```

## cicd

### secretr cicd

- **What**: CI/CD pipeline integration

Flags: none

Minimal Example:

```bash
secretr cicd
```

### secretr cicd create-pipeline

- **What**: Register a pipeline identity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--name` | string | yes | `-` | Pipeline name |
| `--org-id` | string | no | `-` | Organization ID |
| `--provider` | string | yes | `-` | Provider (github, gitlab, etc) |
| `--repo` | string | yes | `-` | Repository identifier |
| `--secret-patterns` | string[] | no | `-` | Secret patterns (e.g., prod/*) |

Minimal Example:

```bash
secretr cicd create-pipeline --name=demo-name --provider=demo-id --repo=owner/repo
```

Full Flags Example:

```bash
secretr cicd create-pipeline --name=demo-name --org-id=demo-id --provider=demo-id --repo=owner/repo --secret-patterns=item1 --secret-patterns=item2
```

### secretr cicd inject

- **What**: Inject secrets into environment

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--branch` | string | no | `-` | Git branch |
| `--env` | string | yes | `-` | Environment name |
| `--pipeline-id` | string | yes | `-` | Pipeline ID |

Minimal Example:

```bash
secretr cicd inject --env=general --pipeline-id=demo-id
```

Full Flags Example:

```bash
secretr cicd inject --branch=main --env=general --pipeline-id=demo-id
```

## compliance

### secretr compliance

- **What**: Compliance reporting and policy enforcement

Flags: none

Minimal Example:

```bash
secretr compliance
```

### secretr compliance frameworks

- **What**: List available compliance frameworks

Flags: none

Minimal Example:

```bash
secretr compliance frameworks
```

### secretr compliance list-reports

- **What**: List generated compliance reports

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr compliance list-reports
```

Full Flags Example:

```bash
secretr compliance list-reports --org-id=demo-id
```

### secretr compliance policy

- **What**: Manage compliance policies

Flags: none

Minimal Example:

```bash
secretr compliance policy
```

### secretr compliance policy create

- **What**: Create policy

Flags: none

Minimal Example:

```bash
secretr compliance policy create
```

### secretr compliance policy list

- **What**: List policies

Flags: none

Minimal Example:

```bash
secretr compliance policy list
```

### secretr compliance policy update

- **What**: Update policy

Flags: none

Minimal Example:

```bash
secretr compliance policy update
```

### secretr compliance report

- **What**: Generate compliance report

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--output` (`-o`) | string | yes | `-` | Output file |
| `--standard` | string | yes | `-` | Compliance standard (e.g., SOC2, GDPR) |

Minimal Example:

```bash
secretr compliance report --output=/tmp/output.json --standard=demo
```

Full Flags Example:

```bash
secretr compliance report --output=/tmp/output.json --standard=demo
```

### secretr compliance score

- **What**: Get compliance score

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |
| `--standard` | string | yes | `-` | Compliance standard |

Minimal Example:

```bash
secretr compliance score --standard=demo
```

Full Flags Example:

```bash
secretr compliance score --org-id=demo-id --standard=demo
```

## data

### secretr data

- **What**: Manage key-value data storage
- **Description**: Data storage operations

Flags: none

Minimal Example:

```bash
secretr data
```

### secretr data delete

- **What**: Delete data from the database
- **Description**: Delete a key-value pair

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--key` (`-k`) | string | yes | `-` | Key name |

Minimal Example:

```bash
secretr data delete --key=demo
```

Full Flags Example:

```bash
secretr data delete --key=demo
```

### secretr data exists

- **What**: Check if key exists in the database
- **Description**: Check if a key exists

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--key` (`-k`) | string | yes | `-` | Key name |

Minimal Example:

```bash
secretr data exists --key=demo
```

Full Flags Example:

```bash
secretr data exists --key=demo
```

### secretr data get

- **What**: Get data from the database
- **Description**: Retrieve a value by key

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--json` (`-j`) | bool | no | `false` | Format output as JSON |
| `--key` (`-k`) | string | yes | `-` | Key name |

Minimal Example:

```bash
secretr data get --key=demo
```

Full Flags Example:

```bash
secretr data get --key=demo
```

### secretr data index

- **What**: Store data and build search indexes
- **Description**: Store data with search indexing

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--json` (`-j`) | bool | no | `false` | Parse value as JSON |
| `--key` (`-k`) | string | yes | `-` | Key name |
| `--prefix` | string | no | `-` | Prefix namespace for schema (e.g. users) |
| `--schema` | string | no | `-` | JSON schema for indexing (SearchSchema) |
| `--value` (`-v`) | string | yes | `-` | Value to store |

Minimal Example:

```bash
secretr data index --key=demo --value=demo
```

Full Flags Example:

```bash
secretr data index --key=demo --prefix=processgate/ --schema=demo --value=demo
```

### secretr data list

- **What**: List keys in the database
- **Description**: List all keys

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--limit` (`-l`) | int | no | `100` | Limit number of keys |
| `--offset` (`-o`) | int | no | `0` | Offset for pagination |
| `--prefix` (`-p`) | string | no | `-` | Filter keys by prefix |

Minimal Example:

```bash
secretr data list
```

Full Flags Example:

```bash
secretr data list --limit=20 --offset=1 --prefix=processgate/
```

### secretr data put

- **What**: Store data in the database
- **Description**: Store a key-value pair

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--json` (`-j`) | bool | no | `false` | Parse value as JSON |
| `--key` (`-k`) | string | yes | `-` | Key name |
| `--ttl` (`-t`) | int | no | `0` | Time to live in seconds (0 = no expiration) |
| `--value` (`-v`) | string | yes | `-` | Value to store |

Minimal Example:

```bash
secretr data put --key=demo --value=demo
```

Full Flags Example:

```bash
secretr data put --key=demo --ttl=1 --value=demo
```

### secretr data search

- **What**: Search values using full-text and filters
- **Description**: Search indexed data

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--filter` | string[] | no | `-` | Filter expression (field==value, field>=value, etc). Repeatable. |
| `--hash-field` | string[] | no | `-` | Field names to use hash equality index (repeatable) |
| `--json` | bool | no | `false` | Output results as JSON |
| `--limit` | int | no | `100` | Maximum results |
| `--prefix` | string | no | `-` | Key prefix namespace to search within |
| `--text` | string | no | `-` | Full-text search query |

Minimal Example:

```bash
secretr data search
```

Full Flags Example:

```bash
secretr data search --filter=item1 --filter=item2 --hash-field=item1 --hash-field=item2 --limit=20 --prefix=processgate/ --text=demo
```

## device

### secretr device

- **What**: Device management

Flags: none

Minimal Example:

```bash
secretr device
```

### secretr device enroll

- **What**: Enroll this device

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--name` (`-n`) | string | yes | `-` | Device name |
| `--type` | string | no | `desktop` | Device type: desktop, mobile, server |

Minimal Example:

```bash
secretr device enroll --name=demo-name
```

Full Flags Example:

```bash
secretr device enroll --name=demo-name --type=demo
```

### secretr device list

- **What**: List enrolled devices

Flags: none

Minimal Example:

```bash
secretr device list
```

### secretr device revoke

- **What**: Revoke a device

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Device ID |

Minimal Example:

```bash
secretr device revoke --id=demo-id
```

Full Flags Example:

```bash
secretr device revoke --id=demo-id
```

### secretr device trust

- **What**: View device trust score

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | no | `-` | Device ID |

Minimal Example:

```bash
secretr device trust
```

Full Flags Example:

```bash
secretr device trust --id=demo-id
```

## dlp

### secretr dlp

- **What**: Data Loss Prevention

Flags: none

Minimal Example:

```bash
secretr dlp
```

### secretr dlp rules

- **What**: Manage DLP rules

Flags: none

Minimal Example:

```bash
secretr dlp rules
```

### secretr dlp rules create

- **What**: Create rule

Flags: none

Minimal Example:

```bash
secretr dlp rules create
```

### secretr dlp rules delete

- **What**: Delete rule

Flags: none

Minimal Example:

```bash
secretr dlp rules delete
```

### secretr dlp rules list

- **What**: List rules

Flags: none

Minimal Example:

```bash
secretr dlp rules list
```

### secretr dlp scan

- **What**: Scan for sensitive data

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` | string | yes | `-` | Path to scan |
| `--rules` | string[] | no | `-` | DLP rules to apply |

Minimal Example:

```bash
secretr dlp scan --path=/tmp/path
```

Full Flags Example:

```bash
secretr dlp scan --path=/tmp/path --rules=item1 --rules=item2
```

## enrich

### secretr enrich

- **What**: Run a command with all secrets injected into environment

Flags: none

Minimal Example:

```bash
secretr enrich
```

## env

### secretr env

- **What**: Output a secret as an environment variable export

Flags: none

Minimal Example:

```bash
secretr env
```

## envelope

### secretr envelope

- **What**: Secure envelope management

Flags: none

Minimal Example:

```bash
secretr envelope
```

### secretr envelope create

- **What**: Create a secure envelope

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--expires-in` | duration | no | `0s` | Expiration duration |
| `--file` (`-f`) | string[] | no | `-` | Files to include (path) |
| `--message` (`-m`) | string | no | `-` | Message to include |
| `--output` (`-o`) | string | yes | `-` | Output file path |
| `--policy` (`-p`) | string | no | `-` | Policy ID |
| `--recipient` (`-r`) | string | yes | `-` | Recipient ID or Email |
| `--require-mfa` | bool | no | `false` | Require MFA to open |
| `--secret` (`-s`) | string[] | no | `-` | Secrets to include (name:value or name) |

Minimal Example:

```bash
secretr envelope create --output=/tmp/output.json --recipient=demo
```

Full Flags Example:

```bash
secretr envelope create --expires-in=24h --file=/tmp/input.json --file=item2 --message=demo --output=/tmp/output.json --policy=demo --recipient=demo --secret=ENCRYPTED_SECRET:ENCRYPTED_SECRET --secret=DB_PASSWORD:DB_PASSWORD
```

### secretr envelope open

- **What**: Open a secure envelope

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--file` (`-f`) | string | yes | `-` | Envelope file path |
| `--inspect` | bool | no | `false` | Inspect metadata only |

Minimal Example:

```bash
secretr envelope open --file=/tmp/input.json
```

Full Flags Example:

```bash
secretr envelope open --file=/tmp/input.json
```

### secretr envelope verify

- **What**: Verify envelope integrity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--file` (`-f`) | string | yes | `-` | Envelope file path |

Minimal Example:

```bash
secretr envelope verify --file=/tmp/input.json
```

Full Flags Example:

```bash
secretr envelope verify --file=/tmp/input.json
```

## exec

### secretr exec

- **What**: Execute command with secrets

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--all-secrets` | bool | no | `false` | Load all secrets as environment variables |
| `--command` | string | yes | `-` | Command to run |
| `--env` | string | no | `-` | Filter bulk-loaded secrets by environment |
| `--env-prefix` | string | no | `-` | Prefix applied to generated environment variable names |
| `--isolation` | string | no | `auto` | Isolation level: auto (default), host, ns (Linux namespaces) |
| `--prefix` | string | no | `-` | Load only secrets under prefix/folder as environment variables |
| `--seccomp-profile` | string | no | `-` | Linux seccomp profile (e.g. strict); strict mode fails closed if unavailable |
| `--secret` (`-s`) | string[] | no | `-` | Secret mapping ID:ENV_VAR or ID:ENV_VAR:file |
| `--strict-sandbox` | bool | no | `false` | Fail command if requested sandbox controls are unavailable |

Minimal Example:

```bash
secretr exec --command=go
```

Full Flags Example:

```bash
secretr exec --command=go --env=general --env-prefix=APP --isolation=demo --prefix=processgate/ --seccomp-profile=/tmp/input.json --secret=ENCRYPTED_SECRET:ENCRYPTED_SECRET --secret=DB_PASSWORD:DB_PASSWORD
```

## export

### secretr export

- **What**: Export secrets, folders, and objects to various formats
- **Description**: Export data to files

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--compress` (`-z`) | bool | no | `false` | Compress output |
| `--format` (`-f`) | string | no | `json` | Export format: json, encrypted-json, tar, tar.gz |
| `--output` (`-o`) | string | yes | `-` | Output file path |
| `--path` (`-p`) | string[] | yes | `-` | Item path(s) to export |
| `--pretty` (`-P`) | bool | no | `true` | Pretty print JSON output |
| `--recursive` (`-r`) | bool | no | `true` | For folders: recursively export all contents |
| `--type` (`-t`) | string | yes | `-` | Item type: secret, folder, object |

Minimal Example:

```bash
secretr export --output=/tmp/output.json --path=/tmp/path --type=demo
```

Full Flags Example:

```bash
secretr export --format=demo --output=/tmp/output.json --path=/tmp/path --path=item2 --type=demo
```

## folder

### secretr folder

- **What**: Manage folders in object storage
- **Description**: Folder management operations

Flags: none

Minimal Example:

```bash
secretr folder
```

### secretr folder copy

- **What**: Copy folder and all contents
- **Description**: Copy a folder

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--dest` (`-d`) | string | yes | `-` | Destination folder path |
| `--source` (`-s`) | string | yes | `-` | Source folder path |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr folder copy --dest=demo --source=demo
```

Full Flags Example:

```bash
secretr folder copy --dest=demo --source=demo --user=demo
```

### secretr folder create

- **What**: Create folder in storage
- **Description**: Create a folder

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Folder path |
| `--paths` (`-m`) | string[] | no | `-` | Multiple folder paths to create (batch mode) |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr folder create --path=/tmp/path
```

Full Flags Example:

```bash
secretr folder create --path=/tmp/path --paths=/tmp/path --paths=item2 --user=demo
```

### secretr folder delete

- **What**: Delete folder from storage
- **Description**: Delete a folder

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Folder path |
| `--recursive` (`-r`) | bool | no | `false` | Delete folder and all contents |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr folder delete --path=/tmp/path
```

Full Flags Example:

```bash
secretr folder delete --path=/tmp/path --user=demo
```

### secretr folder info

- **What**: Get detailed information about a folder
- **Description**: Get folder information

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Folder path |

Minimal Example:

```bash
secretr folder info --path=/tmp/path
```

Full Flags Example:

```bash
secretr folder info --path=/tmp/path
```

### secretr folder list

- **What**: List folders in storage
- **Description**: List folders

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--parent` (`-p`) | string | no | `-` | Parent folder path (empty for all) |
| `--recursive` (`-r`) | bool | no | `false` | List recursively |

Minimal Example:

```bash
secretr folder list
```

Full Flags Example:

```bash
secretr folder list --parent=demo
```

### secretr folder rename

- **What**: Rename or move folder and all contents
- **Description**: Rename or move a folder

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--new` (`-n`) | string | yes | `-` | New folder path |
| `--old` (`-o`) | string | yes | `-` | Old folder path |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr folder rename --new=demo --old=demo
```

Full Flags Example:

```bash
secretr folder rename --new=demo --old=demo --user=demo
```

### secretr folder size

- **What**: Calculate total size of folder contents
- **Description**: Get folder size

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Folder path |
| `--recursive` (`-r`) | bool | no | `true` | Calculate recursively |

Minimal Example:

```bash
secretr folder size --path=/tmp/path
```

Full Flags Example:

```bash
secretr folder size --path=/tmp/path
```

### secretr folder upload

- **What**: Upload local folder to storage
- **Description**: Upload a local folder

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--dest` (`-d`) | string | yes | `-` | Destination folder path in vault |
| `--encrypt` (`-e`) | bool | no | `true` | Encrypt objects |
| `--recursive` (`-r`) | bool | no | `true` | Upload recursively (including subfolders) |
| `--source` (`-s`) | string | yes | `-` | Local folder path to upload |

Minimal Example:

```bash
secretr folder upload --dest=demo --source=demo
```

Full Flags Example:

```bash
secretr folder upload --dest=demo --source=demo
```

### secretr folder view

- **What**: View folder contents using previewer
- **Description**: View folder in browser

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--compress` (`-c`) | bool | no | `true` | Enable compression for text files |
| `--max-file-size` | string | no | `-` | --max-file-size int	Maximum file size in MB (default: 100) |
| `--path` (`-p`) | string | yes | `-` | Folder path in vault |

Minimal Example:

```bash
secretr folder view --path=/tmp/path
```

Full Flags Example:

```bash
secretr folder view --max-file-size=/tmp/input.json --path=/tmp/path
```

## identity

### secretr identity

- **What**: Identity management

Flags: none

Minimal Example:

```bash
secretr identity
```

### secretr identity create

- **What**: Create a new identity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--email` (`-e`) | string | yes | `-` | Email address |
| `--name` (`-n`) | string | yes | `-` | Identity name |
| `--password` (`-p`) | string | no | `-` | Password (will prompt if not provided) |
| `--scopes` (`-s`) | string[] | no | `-` | Permission scopes |
| `--type` (`-t`) | string | no | `human` | Identity type: human, service |

Minimal Example:

```bash
secretr identity create --email=admin@example.com --name=demo-name
```

Full Flags Example:

```bash
secretr identity create --email=admin@example.com --name=demo-name --password=ChangeMe123! --scopes=item1 --scopes=secret:read --type=demo
```

### secretr identity get

- **What**: Get identity details

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Identity ID |

Minimal Example:

```bash
secretr identity get --id=demo-id
```

Full Flags Example:

```bash
secretr identity get --id=demo-id
```

### secretr identity list

- **What**: List identities

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--status` | string | no | `-` | Filter by status |
| `--type` | string | no | `-` | Filter by type |

Minimal Example:

```bash
secretr identity list
```

Full Flags Example:

```bash
secretr identity list --status=demo --type=demo
```

### secretr identity recover

- **What**: Start identity recovery workflow

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--email` | string | yes | `-` | Email address |

Minimal Example:

```bash
secretr identity recover --email=admin@example.com
```

Full Flags Example:

```bash
secretr identity recover --email=admin@example.com
```

### secretr identity revoke

- **What**: Revoke an identity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--force` | bool | no | `false` | Force revocation without confirmation |
| `--id` | string | yes | `-` | Identity ID |

Minimal Example:

```bash
secretr identity revoke --id=demo-id
```

Full Flags Example:

```bash
secretr identity revoke --id=demo-id
```

## import

### secretr import

- **What**: Import secrets, folders, and objects from various formats
- **Description**: Import data from files

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--dry-run` (`-n`) | bool | no | `false` | Show what would be imported without actually importing |
| `--format` (`-f`) | string | no | `auto` | Import format: json, encrypted-json, tar, tar.gz, auto (default: auto) |
| `--input` (`-i`) | string | yes | `-` | Input file path |
| `--overwrite` (`-w`) | bool | no | `false` | Overwrite existing items |

Minimal Example:

```bash
secretr import --input=/tmp/input.json
```

Full Flags Example:

```bash
secretr import --format=demo --input=/tmp/input.json
```

## incident

### secretr incident

- **What**: Incident response

Flags: none

Minimal Example:

```bash
secretr incident
```

### secretr incident declare

- **What**: Declare a security incident

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--description` (`-d`) | string | yes | `-` | Description |
| `--org-id` | string | no | `-` | Organization ID |
| `--severity` | string | no | `high` | Severity: critical, high, medium, low |
| `--type` | string | yes | `-` | Incident type |

Minimal Example:

```bash
secretr incident declare --description=demo --type=demo
```

Full Flags Example:

```bash
secretr incident declare --description=demo --org-id=demo-id --severity=high --type=demo
```

### secretr incident export

- **What**: Export incident evidence

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Incident ID |
| `--org-id` | string | no | `-` | Organization ID |
| `--output` (`-o`) | string | yes | `-` | Output file |

Minimal Example:

```bash
secretr incident export --id=demo-id --output=/tmp/output.json
```

Full Flags Example:

```bash
secretr incident export --id=demo-id --org-id=demo-id --output=/tmp/output.json
```

### secretr incident freeze

- **What**: Freeze organization access

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--disable` | bool | no | `false` | Disable freeze (unfreeze) |
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr incident freeze
```

Full Flags Example:

```bash
secretr incident freeze --org-id=demo-id
```

### secretr incident list

- **What**: List security incidents

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr incident list
```

Full Flags Example:

```bash
secretr incident list --org-id=demo-id
```

### secretr incident rotate

- **What**: Emergency secret rotation

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--all` | bool | no | `false` | Rotate all secrets |
| `--names` | string[] | no | `-` | Specific secrets to rotate |
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr incident rotate
```

Full Flags Example:

```bash
secretr incident rotate --names=item1 --names=SECRET_TWO --org-id=demo-id
```

### secretr incident timeline

- **What**: View incident timeline

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Incident ID |
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr incident timeline --id=demo-id
```

Full Flags Example:

```bash
secretr incident timeline --id=demo-id --org-id=demo-id
```

## key

### secretr key

- **What**: Cryptographic key management

Flags: none

Minimal Example:

```bash
secretr key
```

### secretr key destroy

- **What**: Destroy a key with proof

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--force` | bool | no | `false` | Force destruction without confirmation |
| `--id` | string | yes | `-` | Key ID |

Minimal Example:

```bash
secretr key destroy --id=demo-id
```

Full Flags Example:

```bash
secretr key destroy --id=demo-id
```

### secretr key export

- **What**: Export a key for backup

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Key ID |
| `--output` (`-o`) | string | yes | `-` | Output file |

Minimal Example:

```bash
secretr key export --id=demo-id --output=/tmp/output.json
```

Full Flags Example:

```bash
secretr key export --id=demo-id --output=/tmp/output.json
```

### secretr key generate

- **What**: Generate a new key

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--expires-in` | duration | no | `0s` | Key expiration duration |
| `--purpose` | string | no | `encrypt` | Key purpose |
| `--type` | string | no | `encryption` | Key type: encryption, signing |

Minimal Example:

```bash
secretr key generate
```

Full Flags Example:

```bash
secretr key generate --expires-in=24h --purpose=demo --type=demo
```

### secretr key import

- **What**: Import a key from backup

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--input` (`-i`) | string | yes | `-` | Input file |

Minimal Example:

```bash
secretr key import --input=/tmp/input.json
```

Full Flags Example:

```bash
secretr key import --input=/tmp/input.json
```

### secretr key list

- **What**: List keys

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--status` | string | no | `-` | Filter by status |
| `--type` | string | no | `-` | Filter by type |

Minimal Example:

```bash
secretr key list
```

Full Flags Example:

```bash
secretr key list --status=demo --type=demo
```

### secretr key rotate

- **What**: Rotate a key

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Key ID |

Minimal Example:

```bash
secretr key rotate --id=demo-id
```

Full Flags Example:

```bash
secretr key rotate --id=demo-id
```

### secretr key split

- **What**: Split key for M-of-N recovery

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Key ID |
| `--shares` (`-n`) | int | no | `5` | Total shares |
| `--threshold` (`-t`) | int | no | `3` | Required threshold |

Minimal Example:

```bash
secretr key split --id=demo-id
```

Full Flags Example:

```bash
secretr key split --id=demo-id --shares=1 --threshold=1
```

## load-env

### secretr load-env

- **What**: Output all secrets as environment variable exports

Flags: none

Minimal Example:

```bash
secretr load-env
```

## monitoring

### secretr monitoring

- **What**: System monitoring and behavior analysis

Flags: none

Minimal Example:

```bash
secretr monitoring
```

### secretr monitoring dashboard

- **What**: Show monitoring dashboard

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--period` | string | no | `24h` | Time period (1h, 24h, 7d, 30d) |

Minimal Example:

```bash
secretr monitoring dashboard
```

Full Flags Example:

```bash
secretr monitoring dashboard --period=24h
```

### secretr monitoring events

- **What**: Query monitoring events

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--actor` | string | no | `-` | Filter by actor ID |
| `--limit` | int | no | `20` | Max events to show |
| `--type` | string | no | `-` | Filter by event type |

Minimal Example:

```bash
secretr monitoring events
```

Full Flags Example:

```bash
secretr monitoring events --actor=demo --limit=20 --type=demo
```

## object

### secretr object

- **What**: Manage object/file storage
- **Description**: Object storage operations

Flags: none

Minimal Example:

```bash
secretr object
```

### secretr object delete

- **What**: Delete file from object storage
- **Description**: Delete an object/file

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Object path in storage |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr object delete --path=/tmp/path
```

Full Flags Example:

```bash
secretr object delete --path=/tmp/path --user=demo
```

### secretr object get

- **What**: Download file from object storage
- **Description**: Download an object/file

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--output` (`-o`) | string | yes | `-` | Output file path |
| `--path` (`-p`) | string | yes | `-` | Object path in storage |

Minimal Example:

```bash
secretr object get --output=/tmp/output.json --path=/tmp/path
```

Full Flags Example:

```bash
secretr object get --output=/tmp/output.json --path=/tmp/path
```

### secretr object info

- **What**: Get detailed information about an object
- **Description**: Get object metadata

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Object path in storage |

Minimal Example:

```bash
secretr object info --path=/tmp/path
```

Full Flags Example:

```bash
secretr object info --path=/tmp/path
```

### secretr object list

- **What**: List objects in storage
- **Description**: List objects

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--folder` (`-f`) | string | no | `-` | Filter by folder |
| `--limit` (`-l`) | int | no | `100` | Maximum number of objects |
| `--prefix` (`-p`) | string | no | `-` | Filter by prefix |
| `--recursive` (`-r`) | bool | no | `false` | List recursively |

Minimal Example:

```bash
secretr object list
```

Full Flags Example:

```bash
secretr object list --folder=demo --limit=20 --prefix=processgate/
```

### secretr object put

- **What**: Upload file to object storage
- **Description**: Upload an object/file

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--content-type` (`-c`) | string | no | `-` | Content type (auto-detected if not specified) |
| `--encrypt` (`-e`) | bool | no | `true` | Encrypt the object |
| `--file` (`-f`) | string | yes | `-` | Local file path to upload |
| `--path` (`-p`) | string | yes | `-` | Object path in storage |
| `--tag` (`-t`) | string[] | no | `-` | Tags in format key=value (can specify multiple) |

Minimal Example:

```bash
secretr object put --file=/tmp/input.json --path=/tmp/path
```

Full Flags Example:

```bash
secretr object put --content-type=demo --file=/tmp/input.json --path=/tmp/path --tag=item1 --tag=item2
```

### secretr object view

- **What**: Preview object in browser using viewer
- **Description**: View object in browser

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--path` (`-p`) | string | yes | `-` | Object path in storage |
| `--user` (`-u`) | string | no | `default` | User identifier |

Minimal Example:

```bash
secretr object view --path=/tmp/path
```

Full Flags Example:

```bash
secretr object view --path=/tmp/path --user=demo
```

## org

### secretr org

- **What**: Organization management

Flags: none

Minimal Example:

```bash
secretr org
```

### secretr org create

- **What**: Create an organization

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--name` (`-n`) | string | yes | `-` | Organization name |
| `--slug` | string | no | `-` | URL-friendly slug |

Minimal Example:

```bash
secretr org create --name=demo-name
```

Full Flags Example:

```bash
secretr org create --name=demo-name --slug=demo
```

### secretr org create-vendor

- **What**: Create vendor access

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--name` | string | yes | `-` | Vendor Name |
| `--org-id` | string | no | `-` | Organization ID |
| `--vendor-id` | string | yes | `-` | Vendor Identity ID |

Minimal Example:

```bash
secretr org create-vendor --name=demo-name --vendor-id=demo-id
```

Full Flags Example:

```bash
secretr org create-vendor --name=demo-name --org-id=demo-id --vendor-id=demo-id
```

### secretr org environments

- **What**: Environment management

Flags: none

Minimal Example:

```bash
secretr org environments
```

### secretr org environments create

- **What**: Create environment

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--description` | string | no | `-` | Environment description |
| `--name` | string | yes | `-` | Environment name |
| `--org-id` | string | no | `-` | Organization ID |
| `--type` | string | no | `-` | Environment type (e.g., production, staging) |

Minimal Example:

```bash
secretr org environments create --name=demo-name
```

Full Flags Example:

```bash
secretr org environments create --description=demo --name=demo-name --org-id=demo-id --type=demo
```

### secretr org environments list

- **What**: List environments

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr org environments list
```

Full Flags Example:

```bash
secretr org environments list --org-id=demo-id
```

### secretr org grant-auditor

- **What**: Grant access to external auditor

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--auditor-id` | string | yes | `-` | Auditor Identity ID |
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr org grant-auditor --auditor-id=demo-id
```

Full Flags Example:

```bash
secretr org grant-auditor --auditor-id=demo-id --org-id=demo-id
```

### secretr org invite

- **What**: Invite member to organization

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--email` | string | yes | `-` | Email address |
| `--role` | string | no | `-` | Role to assign |

Minimal Example:

```bash
secretr org invite --email=admin@example.com
```

Full Flags Example:

```bash
secretr org invite --email=admin@example.com --role=demo
```

### secretr org legal-hold

- **What**: Enable legal hold mode

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr org legal-hold
```

Full Flags Example:

```bash
secretr org legal-hold --org-id=demo-id
```

### secretr org list

- **What**: List organizations

Flags: none

Minimal Example:

```bash
secretr org list
```

### secretr org teams

- **What**: Team management

Flags: none

Minimal Example:

```bash
secretr org teams
```

### secretr org teams create

- **What**: Create team

Flags: none

Minimal Example:

```bash
secretr org teams create
```

### secretr org teams list

- **What**: List teams

Flags: none

Minimal Example:

```bash
secretr org teams list
```

### secretr org transfer

- **What**: M&A resource transfer

Flags: none

Minimal Example:

```bash
secretr org transfer
```

### secretr org transfer approve

- **What**: Approve resource transfer

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Transfer ID |

Minimal Example:

```bash
secretr org transfer approve --id=demo-id
```

Full Flags Example:

```bash
secretr org transfer approve --id=demo-id
```

### secretr org transfer execute

- **What**: Execute approved transfer

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Transfer ID |

Minimal Example:

```bash
secretr org transfer execute --id=demo-id
```

Full Flags Example:

```bash
secretr org transfer execute --id=demo-id
```

### secretr org transfer init

- **What**: Initiate transfer between organizations

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--source-org` | string | yes | `-` | Source organization ID |
| `--target-org` | string | yes | `-` | Target organization ID |

Minimal Example:

```bash
secretr org transfer init --source-org=demo --target-org=demo
```

Full Flags Example:

```bash
secretr org transfer init --source-org=demo --target-org=demo
```

## pipeline

### secretr pipeline

- **What**: Manage automation pipelines

Flags: none

Minimal Example:

```bash
secretr pipeline
```

### secretr pipeline apply

- **What**: Apply a pipeline configuration

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--file` (`-f`) | string | yes | `-` | JSON configuration file |

Minimal Example:

```bash
secretr pipeline apply --file=/tmp/input.json
```

Full Flags Example:

```bash
secretr pipeline apply --file=/tmp/input.json
```

### secretr pipeline list

- **What**: List automation pipelines

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--org-id` | string | no | `-` | Organization ID |

Minimal Example:

```bash
secretr pipeline list
```

Full Flags Example:

```bash
secretr pipeline list --org-id=demo-id
```

### secretr pipeline trigger

- **What**: Trigger an automation event

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--event` (`-e`) | string | yes | `-` | Event name |
| `--param` (`-p`) | string[] | no | `-` | Parameter (key=value) |

Minimal Example:

```bash
secretr pipeline trigger --event=demo
```

Full Flags Example:

```bash
secretr pipeline trigger --event=demo --param=item1 --param=user_id=u-123
```

## policy

### secretr policy

- **What**: Policy management

Flags: none

Minimal Example:

```bash
secretr policy
```

### secretr policy bind

- **What**: Bind policy to resource

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--policy` | string | yes | `-` | Policy ID |
| `--resource` | string | yes | `-` | Resource ID |

Minimal Example:

```bash
secretr policy bind --policy=demo --resource=demo
```

Full Flags Example:

```bash
secretr policy bind --policy=demo --resource=demo
```

### secretr policy create

- **What**: Create a policy

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--file` (`-f`) | string | no | `-` | Policy definition file |
| `--name` (`-n`) | string | yes | `-` | Policy name |

Minimal Example:

```bash
secretr policy create --name=demo-name
```

Full Flags Example:

```bash
secretr policy create --file=/tmp/input.json --name=demo-name
```

### secretr policy freeze

- **What**: Enable policy lockdown mode

Flags: none

Minimal Example:

```bash
secretr policy freeze
```

### secretr policy list

- **What**: List policies

Flags: none

Minimal Example:

```bash
secretr policy list
```

### secretr policy simulate

- **What**: Simulate policy evaluation

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--action` | string | yes | `-` | Action to simulate |
| `--policy` | string | yes | `-` | Policy ID |
| `--resource` | string | no | `-` | Resource ID |

Minimal Example:

```bash
secretr policy simulate --action=demo --policy=demo
```

Full Flags Example:

```bash
secretr policy simulate --action=demo --policy=demo --resource=demo
```

## role

### secretr role

- **What**: Role-based access control

Flags: none

Minimal Example:

```bash
secretr role
```

### secretr role assign

- **What**: Assign role to identity

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--identity` | string | yes | `-` | Identity ID |
| `--role` | string | yes | `-` | Role ID |

Minimal Example:

```bash
secretr role assign --identity=demo-id --role=demo
```

Full Flags Example:

```bash
secretr role assign --identity=demo-id --role=demo
```

### secretr role create

- **What**: Create a role

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--description` (`-d`) | string | no | `-` | Description |
| `--name` (`-n`) | string | yes | `-` | Role name |
| `--scopes` (`-s`) | string[] | no | `-` | Scopes |

Minimal Example:

```bash
secretr role create --name=demo-name
```

Full Flags Example:

```bash
secretr role create --description=demo --name=demo-name --scopes=item1 --scopes=secret:read
```

### secretr role list

- **What**: List roles

Flags: none

Minimal Example:

```bash
secretr role list
```

## secret

### secretr secret

- **What**: Manage encrypted secrets
- **Description**: Secret management operations

Flags: none

Minimal Example:

```bash
secretr secret
```

### secretr secret delete

- **What**: Delete encrypted secret
- **Description**: Delete a secret

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--category` (`-c`) | string | no | `general` | Secret category |
| `--name` (`-n`) | string | yes | `-` | Secret name |

Minimal Example:

```bash
secretr secret delete --name=ENCRYPTED_SECRET
```

Full Flags Example:

```bash
secretr secret delete --category=demo --name=ENCRYPTED_SECRET
```

### secretr secret get

- **What**: Get encrypted secret value
- **Description**: Retrieve a secret

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--category` (`-c`) | string | no | `general` | Secret category |
| `--name` (`-n`) | string | yes | `-` | Secret name |
| `--show` (`-s`) | bool | no | `false` | Show secret value (otherwise shows masked) |

Minimal Example:

```bash
secretr secret get --name=ENCRYPTED_SECRET
```

Full Flags Example:

```bash
secretr secret get --category=demo --name=ENCRYPTED_SECRET
```

### secretr secret list

- **What**: List all stored secrets
- **Description**: List all secrets

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--category` (`-c`) | string | no | `-` | Filter by category |

Minimal Example:

```bash
secretr secret list
```

Full Flags Example:

```bash
secretr secret list --category=demo
```

### secretr secret rotate

- **What**: Generate new random value for secret
- **Description**: Rotate a secret

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--category` (`-c`) | string | no | `general` | Secret category |
| `--length` (`-l`) | int | no | `32` | Length of generated secret (in bytes) |
| `--name` (`-n`) | string | yes | `-` | Secret name |

Minimal Example:

```bash
secretr secret rotate --name=ENCRYPTED_SECRET
```

Full Flags Example:

```bash
secretr secret rotate --category=demo --length=1 --name=ENCRYPTED_SECRET
```

### secretr secret set

- **What**: Store encrypted secret value
- **Description**: Store a secret

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--category` (`-c`) | string | no | `general` | Secret category |
| `--name` (`-n`) | string | yes | `-` | Secret name |
| `--ttl` (`-t`) | int | no | `0` | Time to live in seconds (0 = no expiration) |
| `--value` (`-v`) | string | yes | `-` | Secret value |

Minimal Example:

```bash
secretr secret set --name=ENCRYPTED_SECRET --value=demo
```

Full Flags Example:

```bash
secretr secret set --category=demo --name=ENCRYPTED_SECRET --ttl=1 --value=demo
```

## session

### secretr session

- **What**: Session management

Flags: none

Minimal Example:

```bash
secretr session
```

### secretr session list

- **What**: List active sessions

Flags: none

Minimal Example:

```bash
secretr session list
```

### secretr session revoke

- **What**: Revoke a session

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Session ID |

Minimal Example:

```bash
secretr session revoke --id=demo-id
```

Full Flags Example:

```bash
secretr session revoke --id=demo-id
```

### secretr session revoke-all

- **What**: Revoke all sessions except current

Flags: none

Minimal Example:

```bash
secretr session revoke-all
```

## share

### secretr share

- **What**: Secure sharing

Flags: none

Minimal Example:

```bash
secretr share
```

### secretr share accept

- **What**: Accept an incoming share

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |

Minimal Example:

```bash
secretr share accept --id=demo-id
```

Full Flags Example:

```bash
secretr share accept --id=demo-id
```

### secretr share create

- **What**: Create a secure share

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--expires-in` | duration | no | `0s` | Share expiration |
| `--max-access` | int | no | `0` | Maximum access count |
| `--one-time` | bool | no | `false` | One-time access only |
| `--recipient` | string | no | `-` | Recipient identity ID |
| `--resource` (`-r`) | string | yes | `-` | Resource name or ID |
| `--type` | string | yes | `-` | Share type: secret, file, folder, object, envelope |

Minimal Example:

```bash
secretr share create --resource=general:ENCRYPTED_SECRET --type=secret
```

Full Flags Example:

```bash
secretr share create --expires-in=24h --max-access=1 --recipient=<IDENTITY_ID> --resource=/apps/api/config.json --type=object
```

### secretr share export

- **What**: Export share for offline transfer

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |
| `--output` (`-o`) | string | yes | `-` | Output file |

Minimal Example:

```bash
secretr share export --id=demo-id --output=/tmp/output.json
```

Full Flags Example:

```bash
secretr share export --id=demo-id --output=/tmp/output.json
```

### secretr share import

- **What**: Import offline share package

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--input` (`-i`) | string | yes | `-` | Input share package file |
| `--output` (`-o`) | string | no | `-` | Optional output file for imported payload |
| `--password` | string | no | `-` | Recipient password (prompts if omitted) |

Minimal Example:

```bash
secretr share import --input=/tmp/output.json
```

Full Flags Example:

```bash
secretr share import --input=/tmp/output.json --output=/tmp/imported.bin --password='********'
```

### secretr share lan-send

- **What**: Serve encrypted share package over local LAN HTTP

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |
| `--api-url` | string | no | `-` | Advertised base URL override |
| `--bind` | string | no | `0.0.0.0:8787` | Listen address |
| `--qr` | bool | no | `false` | Render terminal QR if qrencode is installed |
| `--ttl` | duration | no | `10m0s` | Sender lifetime while waiting |

Minimal Example:

```bash
secretr share lan-send --id=demo-id
```

Full Flags Example:

```bash
secretr share lan-send --id=demo-id --bind=0.0.0.0:8787 --api-url=http://192.168.1.10:8787 --ttl=10m --qr
```

### secretr share lan-receive

- **What**: Fetch package from LAN sender and import

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--url` | string | yes | `-` | Package URL from sender |
| `--state` | string | no | `-` | Transfer state file path for resumable download |
| `--output` (`-o`) | string | no | `-` | Optional output file for imported payload |
| `--password` | string | no | `-` | Recipient password (prompts if omitted) |

Minimal Example:

```bash
secretr share lan-receive --url=http://192.168.1.10:8787/package/<PACKAGE_ID>
```

Full Flags Example:

```bash
secretr share lan-receive --url=http://192.168.1.10:8787/package/<PACKAGE_ID> --output=/tmp/received.bin --password='********'
```

### secretr share policy-bind

- **What**: Bind policy controls to a share package/import flow

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |
| `--policy-id` | string | yes | `-` | Policy ID |
| `--online-decrypt-required` | bool | no | `false` | Require active online share record at import/decrypt |

Minimal Example:

```bash
secretr share policy-bind --id=demo-id --policy-id=policy-id
```

Full Flags Example:

```bash
secretr share policy-bind --id=demo-id --policy-id=policy-id --online-decrypt-required
```

### secretr share resume

- **What**: Resume LAN transfer/import using a saved transfer state file

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--state` | string | yes | `-` | Transfer state file path |
| `--output` (`-o`) | string | no | `-` | Optional output file for imported payload |
| `--password` | string | no | `-` | Recipient password (prompts if omitted) |

Minimal Example:

```bash
secretr share resume --state=/tmp/share-transfer.json
```

Full Flags Example:

```bash
secretr share resume --state=/tmp/share-transfer.json --output=/tmp/received.bin --password='********'
```

### secretr share transfer-status

- **What**: Inspect transfer checkpoint/status file

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--state` | string | yes | `-` | Transfer state file path |

Minimal Example:

```bash
secretr share transfer-status --state=/tmp/share-transfer.json
```

### Expected Failure Modes (Share E2E)

| Symptom | Error code / message | Why it happens | Fix |
|---|---|---|---|
| Entitlement gate blocks share command | `entitlement_scope_required` | Active license does not include required `share:*` scope | Add required share scopes to license entitlements |
| ACL gate blocks operation | `acl_denied` or `resource id required for ACL evaluation` | Caller lacks ACL permission on target or command did not resolve resource ID | Grant ACL on target resource and pass correct `--id` / selector flags |
| Recipient cannot decrypt imported package | `share: decrypt key not found` (or decrypt failure) | Package encrypted for different recipient key/device | Re-create share for intended recipient identity/device |
| Import fails after revocation | `share: has been revoked` | Sender revoked share and revocation marker is enforced | Expected behavior; create a new share package |
| LAN receive cannot connect | `curl: (7)` / connection refused | Sender not reachable on LAN or wrong URL/bind address | Verify sender is running, URL is correct, firewall/network allows reachability |

### secretr share list

- **What**: List shares

Flags: none

Minimal Example:

```bash
secretr share list
```

### secretr share revoke

- **What**: Revoke a share

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |

Minimal Example:

```bash
secretr share revoke --id=demo-id
```

Full Flags Example:

```bash
secretr share revoke --id=demo-id
```

### secretr share qr-generate

- **What**: Generate QR code for share accept URL/payload

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | yes | `-` | Share ID |
| `--api-url` | string | no | `-` | Base API URL for online accept |
| `--output` (`-o`) | string | no | `-` | PNG output path (requires qrencode) |

Minimal Example:

```bash
secretr share qr-generate --id=demo-id
```

Full Flags Example:

```bash
secretr share qr-generate --id=demo-id --api-url=https://host:9090 --output=/tmp/share.png
```

### secretr share qr-decode

- **What**: Decode QR image payload

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--input` (`-i`) | string | yes | `-` | Input QR image path (requires zbarimg) |

Minimal Example:

```bash
secretr share qr-decode --input=/tmp/share.png
```

Full Flags Example:

```bash
secretr share qr-decode --input=/tmp/share.png
```

### secretr share webrtc-offer

- **What**: Automatic WebRTC sender (can create+transfer in one command)

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--id` | string | conditional | `-` | Existing share ID (or provide type/resource/recipient) |
| `--type` | string | conditional | `-` | Required if `--id` omitted |
| `--resource` | string | conditional | `-` | Required if `--id` omitted |
| `--recipient` | string | conditional | `-` | Required if `--id` omitted |
| `--api-url` | string | no | `-` | Advertised base URL override |
| `--bind` | string | no | `0.0.0.0:8789` | Signaling listen address |
| `--qr` | bool | no | `false` | Render receiver URL as QR |
| `--stun` | string | no | `stun:stun.l.google.com:19302` | STUN URL |
| `--timeout` | duration | no | `5m0s` | Timeout |
| `--ttl` | duration | no | `10m0s` | Signaling endpoint lifetime |

Minimal Example:

```bash
secretr share webrtc-offer --id=demo-id
```

Full Flags Example:

```bash
secretr share webrtc-offer --type=secret --resource=general:ENCRYPTED_SECRET --recipient=<IDENTITY_ID> --bind=0.0.0.0:8789 --api-url=http://192.168.1.10:8789 --ttl=10m --stun=stun:stun.l.google.com:19302 --timeout=5m --qr
```

### secretr share webrtc-answer

- **What**: Automatic WebRTC receiver (fetch offer URL, send answer, receive/import)

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--url` | string | yes | `-` | Sender URL from webrtc-offer output |
| `--output` (`-o`) | string | no | `-` | Optional output file for imported payload |
| `--password` | string | no | `-` | Recipient password (prompts if omitted) |
| `--stun` | string | no | `stun:stun.l.google.com:19302` | STUN URL |
| `--timeout` | duration | no | `5m0s` | Timeout |

Minimal Example:

```bash
secretr share webrtc-answer --url=http://192.168.1.10:8789/webrtc/<TOKEN>
```

Full Flags Example:

```bash
secretr share webrtc-answer --url=http://192.168.1.10:8789/webrtc/<TOKEN> --output=/tmp/received.bin --password='********' --stun=stun:stun.l.google.com:19302 --timeout=5m
```

## ssh

### secretr ssh

- **What**: SSH profile and session management

Flags: none

Minimal Example:

```bash
secretr ssh
```

### secretr ssh create-profile

- **What**: Create an SSH profile

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--host` | string | yes | `-` | Host address |
| `--key-id` | string | yes | `-` | Identity Key ID |
| `--name` | string | yes | `-` | Profile name |
| `--user` | string | yes | `-` | Username |

Minimal Example:

```bash
secretr ssh create-profile --host=demo --key-id=demo-id --name=demo-name --user=demo
```

Full Flags Example:

```bash
secretr ssh create-profile --host=demo --key-id=demo-id --name=demo-name --user=demo
```

### secretr ssh list-profiles

- **What**: List SSH profiles

Flags: none

Minimal Example:

```bash
secretr ssh list-profiles
```

### secretr ssh start

- **What**: Start SSH session

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `--profile-id` | string | yes | `-` | Profile ID |

Minimal Example:

```bash
secretr ssh start --profile-id=demo-id
```

Full Flags Example:

```bash
secretr ssh start --profile-id=demo-id
```

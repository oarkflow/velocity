# Secretr - Military-grade Secrets Management Platform

Secretr is a comprehensive platform for secure secret management, file encryption, identity management, and secure sharing. It enforces authority, preserves evidence, survives disasters, and reduces trust ambiguity.

## Table of Contents
- [Installation](#installation)
- [Architecture](#architecture)
- [Performance Benchmarks](#performance-benchmarks)
- [Security Hardening](#security-hardening)
- [CLI Reference](#cli-reference)
  - [Global Flags](#global-flags)
  - [Authentication](#authentication-auth)
  - [Identity Management](#identity-management-identity)
  - [Device Management](#device-management-device)
  - [Session Management](#session-management-session)
  - [Key Management](#key-management-key)
  - [Secret Management](#secret-management-secret)
  - [File Encryption & Protection](#file-encryption--protection-file)
  - [Folder Encryption & Management](#folder-encryption--management-folder)
  - [Access Control](#access-control-access)
  - [Role Management](#role-management-role)
  - [Policy Management](#policy-management-policy)
  - [Audit Logging & Compliance](#audit-logging--compliance-audit-compliance)
  - [Secure Sharing](#secure-sharing-share)
  - [Backup & Recovery](#backup--recovery-backup)
  - [Organization Management](#organization-management-org)
- [Automation Pipelines](#automation-pipelines-pipeline)
- [Incident Response](#incident-response-incident)
  - [Incident Response](#incident-response-incident)
  - [Secure Envelopes](#secure-envelopes-envelope)
  - [Administration](#administration-admin)
  - [SSH Management](#ssh-management-ssh)
  - [CI/CD Integration](#cicd-integration-cicd)
  - [Execution & Environment](#execution--environment)
  - [Monitoring & Alerting](#monitoring--alerting-monitoring-alert)
- [API Reference](#api-reference)

## Installation

```bash
# Install using Go
go install github.com/oarkflow/velocity/cmd/secretr@latest

# Or build from source
git clone github.com/oarkflow/velocity
cd secretr
go build -o secretr ./cmd/secretr
```

## Performance Benchmarks

Secretr-v2 is designed for high-performance secure operations. All benchmarks were performed on Apple M2 Pro (10-core).

| Operation | Performance | Details |
|-----------|-------------|---------|
| Secret Retrieval | **8.8 µs/op** | Decryption + Access Log |
| Audit Logging | **69 µs/op** | Disk Persist + Hash Chain |
| AES-256-GCM (Encrypt) | **850 ns/op** | 46B Payload |
| Ed25519 (Sign) | **18 µs/op** | Audit Ledger Signing |

## Security Hardening

Secretr-v2 implements several production-grade security features:

- **User-Provided Master Key**: All vault data is encrypted with a user-provided master key combined with device fingerprint
- **Master Key Caching**: Master key is cached for 30 seconds to balance security and usability
- **Device Binding**: Master key is bound to device fingerprint for additional security
- **Strict-Transport-Security (HSTS)**: 1-year max-age with subdomains.
- **Content Security Policy (CSP)**: `default-src 'self'` for API and management UI.
- **X-Frame-Options: DENY**: Prevents clickjacking.
- **X-Content-Type-Options: nosniff**: Prevents MIME-sniffing.
- **TLS 1.3 Support**: Native support for encrypted transport.
- **Zero-Knowledge Audit Ledger**: Tamper-proof logs using Merkle Trees and Schnorr ZK proofs.
- **Cross-Platform Sandbox Isolation**: Linux namespaces/cgroups with fallback controls, macOS `sandbox-exec` best-effort fallback, and Windows process-group isolation.

---

## Dot Notation Support

Secretr supports dot notation for both setting and retrieving nested JSON values, making it easy to work with structured configuration data.

### Setting Nested Values

```bash
# Create nested structure automatically
secretr secret create --name mysql.host --value localhost
secretr secret create --name mysql.port --value 3306
secretr secret create --name mysql.credentials.username --value admin

# Set JSON values directly
secretr secret create --name tenant.aws --value '{"access_key":"key1","secret_key":"secret1"}'

# Deep nesting
secretr secret create --name app.config.database.pool.max_connections --value 100
```

### Retrieving Nested Values

```bash
# Get entire nested structure
secretr secret get mysql
# Output: {"host":"localhost","port":"3306","credentials":{"username":"admin"}}

# Get specific nested values
secretr secret get mysql.host
# Output: localhost

secretr secret get mysql.credentials.username
# Output: admin

# Get JSON field from stored JSON
secretr secret get tenant.aws.access_key
# Output: key1
```

### How It Works

- **Setting**: When you use dot notation in secret names, Secretr automatically creates or merges JSON structures
- **Getting**: Dot notation traverses JSON objects to extract specific values
- **Merging**: Adding new nested keys to existing secrets merges them into the JSON structure
- **Type Detection**: Values are automatically detected as JSON or plain text

---

## CLI Reference

### Global Flags
These flags can be used with any command.
- `--config, -c`: Path to configuration file (default: `~/.secretr/config.yaml`)
- `--format, -f`: Output format: `json`, `yaml`, `table`, `plain` (default: `table`)
- `--quiet`: Suppress non-essential output
- `--debug`: Enable debug output
- `--yes, -y`: Automatic yes to prompts; assume "yes" as answer to all prompts and run non-interactively

### Authentication (`auth`)
Manage user authentication and sessions with master key security.

**`secretr auth init`**
Initialize the system by creating the first administrator account.
- `--name`: Admin name
- `--full-name`: Admin full name
- `--username, -u`: Admin username (compat)
- `--email`: Admin email
- `--password`: Admin password
- `--device-id`: Initial Device ID
- `--idle-timeout`: Session idle timeout (e.g., 24h, 30m) (default: 24h)

**Master Key Security**: During initialization, you must set a master key that encrypts all vault data. This master key is combined with your device fingerprint for additional security.

**`secretr auth login`**
Authenticate and create a new session.
- `--email, -e`: Email address
- `--username, -u`: Username (compat)
- `--password, -p`: Password (will prompt if not provided)
- `--mfa-token`: MFA token if enabled
- `--device-id`: Device ID identification
- `--offline`: Create an offline-capable session

**Master Key Prompt**: After successful password authentication, you'll be prompted for your master key. The master key is cached for 30 seconds to allow multiple commands without re-entering it.

**`secretr auth logout`**
End the current session.

**`secretr auth status`**
Show the status of the current session, including user details and scopes.

**`secretr auth rotate-token`**
Rotate the current session token for security.

**`secretr auth mfa`**
Verify MFA for the current session.
- `--token, -t`: MFA token (Required)

### Identity Management (`identity`)
Manage users, service accounts, and their permissions.

**`secretr identity create`**
Create a new identity.
- `--name, -n`: Identity name (Required)
- `--email, -e`: Email address (Required)
- `--type, -t`: Identity type: `human` or `service` (default: `human`)
- `--password, -p`: Password
- `--scopes, -s`: Permission scopes to assign

**`secretr identity list`**
List all identities.
- `--type`: Filter by type
- `--status`: Filter by status

**`secretr identity get`**
Get details of a specific identity.
- `--id`: Identity ID (Required)

**`secretr identity revoke`**
Revoke an identity, invalidating their access.
- `--id`: Identity ID (Required)
- `--force`: Force revocation without confirmation

**`secretr identity recover`**
Start an identity recovery workflow (e.g., lost password).
- `--email`: Email address (Required)

### Device Management (`device`)
Manage trusted devices.

**`secretr device enroll`**
Enroll the current device.
- `--name, -n`: Device name (Required)
- `--type`: Device type: `desktop`, `mobile`, `server` (default: `desktop`)

**`secretr device list`**
List all enrolled devices.

**`secretr device revoke`**
Revoke a device, preventing further access from it.
- `--id`: Device ID (Required)

**`secretr device trust`**
View the trust score of a device.
- `--id`: Device ID

### Session Management (`session`)
Manage active sessions.

**`secretr session list`**
List all active sessions.

**`secretr session revoke`**
Revoke a specific session.
- `--id`: Session ID (Required)

**`secretr session revoke-all`**
Revoke all sessions except the current one.

### Key Management (`key`)
Manage cryptographic keys.

**`secretr key generate`**
Generate a new key.
- `--type`: Key type: `encryption`, `signing` (default: `encryption`)
- `--purpose`: Key purpose (default: `encrypt`)
- `--expires-in`: Key expiration duration (e.g., `24h`)

**`secretr key list`**
List keys.
- `--type`: Filter by type
- `--status`: Filter by status

**`secretr key rotate`**
Rotate a key, creating a new version.
- `--id`: Key ID (Required)

**`secretr key destroy`**
Destroy a key. **Irreversible**.
- `--id`: Key ID (Required)
- `--force`: Force destruction without confirmation

**`secretr key export`**
Export a key for backup.
- `--id`: Key ID (Required)
- `--output, -o`: Output file path (Required)

**`secretr key import`**
Import a key from a backup.
- `--input, -i`: Input file path (Required)

**`secretr key split`**
Split a key using Shamir's Secret Sharing.
- `--id`: Key ID (Required)
- `--shares, -n`: Total number of shares to create (default: 5)
- `--threshold, -t`: Number of shares required to reconstruct (default: 3)

### Secret Management (`secret`)
Manage secrets (API keys, passwords, etc.).

**`secretr secret create`**
Create a new secret with support for dot notation and JSON values.
- `--name, -n`: Secret name (Required) - supports dot notation for nested values
- `--value, -v`: Secret value (use `-` to read from stdin) - supports JSON strings
- `--type, -t`: Secret type (default: `generic`)
- `--env, -e`: Environment (e.g., `prod`, `dev`)
- `--expires-in`: Expiration duration
- `--read-once`: Secret can only be read once, then is deleted (Burn-after-read)
- `--immutable`: Secret cannot be updated
- `--require-mfa`: Require MFA to access this secret

**Dot Notation Support:**
- `secretr secret create --name mysql.host --value localhost` - Creates nested structure
- `secretr secret create --name app.config.db.port --value 5432` - Deep nesting
- `secretr secret create --name tenant.aws --value '{"key":"val"}'` - JSON values

**`secretr secret get`**
Retrieve a secret's value and metadata with dot notation support.
- `--name, -n`: Secret name (Required) - supports dot notation for nested access
- `--version`: Specific version to retrieve
- `--metadata-only`: Only show metadata, not the value

**Dot Notation Examples:**
- `secretr secret get mysql.host` - Get nested value
- `secretr secret get tenant.aws.secret_key` - Get specific JSON field
- `secretr secret get app.config` - Get entire nested object

**`secretr secret list`**
List secrets.
- `--prefix`: Filter by name prefix
- `--env`: Filter by environment
- `--type`: Filter by type

**`secretr secret update`**
Update an existing secret (creates a new version).
- `--name, -n`: Secret name (Required)
- `--value, -v`: New value

**`secretr secret delete`**
Delete a secret.
- `--name, -n`: Secret name (Required)
- `--force`: Force deletion

**`secretr secret history`**
View version history of a secret.
- `--name, -n`: Secret name (Required)

**`secretr secret rotate`**
Trigger rotation for a secret.
- `--name, -n`: Secret name (Required)

**`secretr secret export`**
Export secrets for offline use.
- `--names`: List of specific secret names
- `--output, -o`: Output file path (Required)

### File Encryption & Protection (`file`)
Encrypt and manage large files in the vault.

**`secretr file upload`**
Upload and encrypt a local file into the vault.
- `--name, -n`: File name in vault (Required)
- `--path, -p`: Local file path (Required)
- `--expires-in`: Expiration duration
- `--overwrite`: Overwrite if exists

**`secretr file download`**
Decrypt and download a file from the vault.
- `--name, -n`: File name in vault (Required)
- `--output, -o`: Output path (Required)

**`secretr file list`**
List stored files.
- `--prefix`: Filter by prefix

**`secretr file delete`**
Delete a file from the vault.
- `--name, -n`: File name (Required)

**`secretr file seal`**
Seal a file for long-term storage (WORM compliance).
- `--name, -n`: File name (Required)

**`secretr file unseal`**
Unseal a file (requires privileged access).
- `--name, -n`: File name (Required)

**`secretr file shred`**
Cryptographically destroy a file, making it unrecoverable.
- `--name, -n`: File name (Required)
- `--force`: Skip confirmation

**`secretr file protect`**
Set file protection policies.
- `--name, -n`: File name (Required)
- `--max-downloads`: Maximum allowed downloads before file is locked/deleted
- `--geofence`: Allowed countries (comma-separated ISO codes)
- `--remote-kill`: Enable remote kill for this file
- `--require-mfa`: Require MFA to access this file

**`secretr file kill`**
Emergency remote kill. Immediately revokes access to the file globally.
- `--name, -n`: File name (Required)
- `--reason`: Reason for kill

**`secretr file revive`**
Revive a killed file.
- `--name, -n`: File name (Required)

### Folder Encryption & Management (`folder`)
Encrypt and manage entire folders with all their contents.

**`secretr folder lock`**
Lock and encrypt a folder while keeping the original.
- `--path, -p`: Folder path to lock (Required)
- `--name, -n`: Name for locked folder in vault (default: folder name + ".locked")

**`secretr folder unlock`**
Unlock and decrypt a folder to a specified location.
- `--name, -n`: Name of locked folder in vault (Required)
- `--output, -o`: Output path for unlocked folder (Required)

**`secretr folder hide`**
Hide a folder by encrypting it and removing the original.
- `--path, -p`: Folder path to hide (Required)
- `--name, -n`: Name for hidden folder in vault (default: folder name + ".hidden")

**`secretr folder show`**
Show a hidden folder by decrypting and restoring it.
- `--name, -n`: Name of hidden folder in vault (Required)
- `--output, -o`: Output path for restored folder (Required)

**Folder Operations:**
- **Lock**: Encrypts folder contents into a secure archive while preserving the original
- **Hide**: Encrypts folder contents and removes the original (more secure)
- **Unlock/Show**: Decrypts and extracts folder contents to specified location
- All folder operations preserve file permissions and directory structure
- Metadata includes file count, total size, and original path for audit purposes

### Access Control (`access`)
Manage access grants.

**`secretr access grant`**
Grant access to a resource for an identity.
- `--grantee, -g`: Grantee Identity ID (Required)
- `--resource, -r`: Resource ID (Required)
- `--type`: Resource type: `secret`, `file`, `key`
- `--scopes, -s`: Specific scopes to grant
- `--expires-in`: Grant expiration
- `--resharing`: Allow grantee to reshare

**`secretr access revoke`**
Revoke an access grant.
- `--id`: Grant ID (Required)

**`secretr access list`**
List access grants.
- `--resource`: Filter by resource
- `--grantee`: Filter by grantee

### Role Management (`role`)
RBAC management.

**`secretr role create`**
Create a new role.
- `--name, -n`: Role name (Required)
- `--description, -d`: Description
- `--scopes, -s`: Permission scopes

**`secretr role list`**
List roles.

**`secretr role assign`**
Assign a role to an identity.
- `--role`: Role ID (Required)
- `--identity`: Identity ID (Required)

### Policy Management (`policy`)
Manage security policies (Policy-as-Code).

**`secretr policy create`**
Create a new policy.
- `--name, -n`: Policy name (Required)
- `--file, -f`: Policy definition file (Rego/JSON)

**`secretr policy list`**
List policies.

**`secretr policy bind`**
Bind a policy to a resource.
- `--policy`: Policy ID (Required)
- `--resource`: Resource ID (Required)

**`secretr policy simulate`**
Simulate policy evaluation against an action.
- `--policy`: Policy ID (Required)
- `--action`: Action to simulate (Required)
- `--resource`: Resource ID

**`secretr policy freeze`**
Enable policy lockdown mode (admin only).

### Audit Logging & Compliance (`audit`)
Search and verify audit logs.

**`secretr audit query`**
Query the audit log.
- `--actor`: Filter by actor ID
- `--resource`: Filter by resource ID
- `--action`: Filter by action
- `--start`: Start timestamp
- `--end`: End timestamp
- `--limit`: Result limit (default: 100)

**`secretr audit export`**
Export signed audit logs.
- `--output, -o`: Output file (Required)
- `--start`: Start time
- `--end`: End time

**`secretr audit verify`**
Verify the cryptographic integrity of the audit log chain (using Merkle Trees and Schnorr ZK Proofs).

**`secretr compliance assess`**
Run automated compliance assessments.
- `--framework`: Compliance framework (GDPR, HIPAA, SOC2)

**`secretr compliance report`**
Generate compliance reports.
- `--format`: Report format (html, json, siem)
- `--output, -o`: Output path

### Secure Sharing (`share`)
Share secrets/files via secure links/invites.

**`secretr share create`**
Create a share.
- `--type`: `secret` or `file` (Required)
- `--resource, -r`: Resource name/ID (Required)
- `--recipient`: Recipient Identity ID
- `--expires-in`: Expiration duration
- `--max-access`: Max access events
- `--one-time`: One-time access only

**`secretr share list`**
List active shares.

**`secretr share revoke`**
Revoke a share.
- `--id`: Share ID (Required)

**`secretr share accept`**
Accept an incoming share.
- `--id`: Share ID (Required)

**`secretr share export`**
Export a share for offline transfer.
- `--id`: Share ID (Required)
- `--output, -o`: Output file (Required)

### Backup & Recovery (`backup`)
Manage system backups.

**`secretr backup create`**
Create an encrypted backup.
- `--output, -o`: Output file (Required)
- `--collections`: Specific collections to backup

**`secretr backup verify`**
Verify backup integrity.
- `--input, -i`: Backup file (Required)

**`secretr backup restore`**
Restore system from backup.
- `--input, -i`: Backup file (Required)
- `--dry-run`: Simulate restore

**`secretr backup schedule`**
Schedule automated backups.
- `--cron`: Cron expression (Required)
- `--destination`: Backup destination path

### Organization Management (`org`)
Multi-tenancy and team management.

**`secretr org create`**
Create a new organization.
- `--name, -n`: Org name (Required)
- `--slug`: URL-friendly slug

**`secretr org list`**
List organizations.

**`secretr org invite`**
Invite a user to an organization.
- `--email`: Email address (Required)
- `--role`: Role to assign

**`secretr org teams create`**
Create a team.

**`secretr org teams list`**
List teams.

**`secretr org environments create`**
Create an environment (e.g., prod, staging).
- `--name`: Name (Required)
- `--org-id`: Org ID
- `--type`: Type
- `--description`: Description

**`secretr org environments list`**
List environments.

**`secretr org legal-hold`**
Enable legal hold (preserves all data, prevents deletions).

**`secretr org grant-auditor`**
Grant read-only access to an external auditor.
- `--auditor-id`: Auditor Identity ID (Required)
- `--org-id`: Org ID

**`secretr org create-vendor`**
Create access for a third-party vendor.
- `--name`: Vendor Name (Required)
- `--vendor-id`: Vendor Identity ID (Required)
- `--org-id`: Org ID

**`secretr org init-transfer`**
Initiate an M&A data transfer.
- `--source-org`: Source Org ID (Required)
- `--target-org`: Target Org ID (Required)

### Automation Pipelines (`pipeline`)
Manage automated sequences of actions triggered by lifecycle events.

**`secretr pipeline apply`**
Apply a pipeline configuration from a JSON file.
- `--file, -f`: Path to pipeline JSON file (Required)

**`secretr pipeline list`**
List all automation pipelines for an organization.
- `--org-id`: Organization ID (Required)

**`secretr pipeline trigger`**
Manually trigger a pipeline event.
- `--event`: Event name (e.g., `enrollment`) (Required)
- `--param`: Additional parameters in `key=value` format
- `--org-id`: Organization ID

**Dynamic Function Support:**
Pipelines support dynamic interpolation and functions:
- `{{user_id}}` - Standard parameter interpolation
- `{{generateToken(user_id)}}` - Dynamic function execution with argument resolution

---

### Incident Response (`incident`)
Manage security incidents.

**`secretr incident declare`**
Declare a security incident.
- `--type`: Incident type (Required)
- `--severity`: `critical`, `high`, `medium`, `low` (default: `high`)
- `--description, -d`: Description (Required)

**`secretr incident freeze`**
Freeze all access for the organization.

**`secretr incident rotate`**
Emergency rotation of secrets.
- `--all`: Rotate ALL secrets
- `--names`: Specific secrets

**`secretr incident export`**
Export incident evidence chain.
- `--id`: Incident ID (Required)
- `--output, -o`: Output file (Required)

**`secretr incident timeline`**
View incident timeline.
- `--id`: Incident ID (Required)

### Secure Envelopes (`envelope`)
Send multiple items securely with policy.

**`secretr envelope create`**
Create a secure envelope.
- `--recipient, -r`: Recipient ID/Email (Required)
- `--secret, -s`: Secrets to include
- `--file, -f`: Files to include
- `--message, -m`: Message
- `--policy, -p`: Policy ID
- `--output, -o`: Output file (Required)
- `--expires-in`: Expiration
- `--require-mfa`: Require MFA to open

**`secretr envelope open`**
Open an envelope.
- `--file, -f`: Envelope file (Required)
- `--inspect`: Inspect metadata only

**`secretr envelope verify`**
Verify envelope integrity.
- `--file, -f`: Envelope file (Required)

### Administration (`admin`)
System administration.

**`secretr admin server`**
Start the Secretr API server.
- `--addr`: Server address (default: `:9090`)
- `--cert`: Path to TLS certificate
- `--key`: Path to TLS private key

**`secretr admin users`**
User administration.

**`secretr admin system`**
System health and status.

**`secretr admin security`**
Security settings configuration.

### SSH Management (`ssh`)
Manage SSH keys and sessions.

**`secretr ssh create-profile`**
Create an SSH profile.
- `--name`: Profile name (Required)
- `--host`: Host address (Required)
- `--user`: Username (Required)
- `--key-id`: Identity Key ID (Required)

**`secretr ssh list-profiles`**
List SSH profiles.

**`secretr ssh start`**
Start an SSH session using the profile.
- `--profile-id`: Profile ID (Required)

### CI/CD Integration (`cicd`)
Pipeline integration.

**`secretr cicd create-pipeline`**
Register a CI/CD pipeline identity using OIDC Federation.
- `--name`: Pipeline name (Required)
- `--provider`: Provider (e.g., `github`) (Required)
- `--repo`: Repo identifier (Required)
- `--org-id`: Org ID

**`secretr cicd inject`**
Inject secrets into a build environment.
- `--pipeline-id`: Pipeline ID (Required)
- `--env`: Environment name (Required)
- `--branch`: Git branch

### Execution & Environment
Runtime secret injection and container isolation.

**`secretr exec`**
Execute a command with secrets injected and sandbox isolation.
- `--command`: Command to run (Required)
- `--secret, -s`: Secret mapping `ID:ENV_VAR`
- `--isolation`: Isolation level (`auto`, `host`, `ns`)
- `--seccomp-profile`: Linux seccomp profile (for example `strict`)
- `--strict-sandbox`: Fail closed if requested sandbox controls are not available

**`secretr env`**
Output a secret as an export command (e.g., `export VAR=value`).

**`secretr load-env`**
Output all available secrets as export commands.

**`secretr enrich`**
Run a command with all available secrets injected.

### Monitoring & Alerting (`monitoring`, `alert`)
View system health and security events.

**`secretr monitoring dashboard`**
View system security metrics and behavior analysis.
- `--period`: Time period (1h, 24h, 7d, 30d)

**`secretr monitoring events`**
Query real-time monitoring events with risk scoring.
- `--type`: Event type
- `--actor`: Actor ID
- `--limit`: Max results

**`secretr alert list`**
List active security alerts.
- `--status`: Filter by status (open, acknowledged, resolved)
- `--severity`: Filter by severity

**`secretr alert ack`**
Acknowledge an alert.
- `--id`: Alert ID (Required)

**`secretr alert resolve`**
Resolve an alert.
- `--id`: Alert ID (Required)

---

## API Reference

The Secretr REST API is served at `/api/v1`.
All requests must include the `Authorization` header:
`Authorization: Bearer <session_id>`

### Authentication

`POST /api/v1/auth/login`
Authenticate and obtain a session token.
**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "device_id": "device-123"
}
```
**Response:**
```json
{
  "session_id": "sess_...",
  "expires_at": "2024-01-01T00:00:00Z",
  "scopes": ["secret:read", ...]
}
```

`POST /api/v1/auth/logout`
Invalidate current session.

`POST /api/v1/auth/refresh`
Refresh current session.

### Secrets

`GET /api/v1/secrets`
List secrets.
**Params:** `prefix`, `environment`

`POST /api/v1/secrets`
Create a new secret (supports `read_once`, `immutable`, `require_mfa`).
**Request:**
```json
{
  "name": "db_password",
  "type": "generic",
  "value": "supersecret",
  "environment": "prod",
  "read_once": false,
  "immutable": false
}
```

`GET /api/v1/secrets/:name`
Retrieve a secret.
**Params:** `metadata=true` (optional - to skip value retrieval)
**Response:**
```json
{
  "name": "db_password",
  "value": "supersecret"
}
```

`PUT /api/v1/secrets/:name`
Update a secret.
**Request:**
```json
{
  "value": "newpassword"
}
```

`DELETE /api/v1/secrets/:name`
Delete a secret.

### Identities

`GET /api/v1/identities`
List identities.

`GET /api/v1/identities/:id`
Get identity details.


### Files

`POST /api/v1/files/:name/kill`
Emergency remote kill.

`POST /api/v1/files/:name/revive`
Revive a killed file.

`POST /api/v1/files/:name/protect`
Update protection policy (geofencing, remote kill, mfa).

### Monitoring & Alerts

`GET /api/v1/monitoring/dashboard`
Get security dashboard metrics.
**Params:** `period` (Go duration format, e.g. `24h`, `168h`)

`GET /api/v1/monitoring/events`
Query monitoring events.
**Params:** `type`, `actor`, `start`, `end`, `limit`

`GET /api/v1/alerts`
List alerts.
**Params:** `status`, `severity`

`GET /api/v1/alerts/:id`
Get alert details.

`POST /api/v1/alerts/:id/acknowledge`
Acknowledge alert.

`POST /api/v1/alerts/:id/resolve`
Resolve alert.

### CI/CD Auth

`POST /api/v1/cicd/auth`
OIDC-based authentication for pipelines.

### Audit

`GET /api/v1/audit`
Query audit logs.
**Params:**
- `actor_id`: Filter by actor
- `resource_id`: Filter by resource
- `action`: Filter by action
- `start`: Start timestamp
- `end`: End timestamp
- `limit`: Max results

`GET /api/v1/audit/export`
Export signed audit logs.
**Response:** JSON file download.

### Health

`GET /health`
Service health check. Checks if API is running.

`GET /ready`
Readiness check. Verifies all dependencies (DB, Vault, etc.) are available.

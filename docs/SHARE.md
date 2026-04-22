# SHARE Command Deep-Dive

`secretr share` provides secure sharing for `secret`, `file`, `object`, `folder`, and `envelope` resources.

This guide is implementation-accurate for current CLI/API behavior, including offline packages, LAN transfer, and automatic WebRTC handshake.

## 1. Command Surface

Top-level group:
- `secretr share`

Subcommands:
- `secretr share create`
- `secretr share list`
- `secretr share revoke`
- `secretr share accept`
- `secretr share export`
- `secretr share import`
- `secretr share qr-generate`
- `secretr share qr-decode`
- `secretr share lan-send`
- `secretr share lan-receive`
- `secretr share webrtc-offer`
- `secretr share webrtc-answer`

Primary implementation files:
- `internal/secretr/cli/commands/share.go`
- `internal/secretr/cli/app/app.go`
- `internal/secretr/core/share/manager.go`
- `internal/secretr/api/server.go`

## 2. Resource Types and What `--resource` Means

`share create --type ... --resource ...` expects:

- `secret`: secret key/name (for example `general:ENCRYPTED_SECRET`)
- `file`: file/object ID resolvable by file vault
- `object`: object path/id from velocity object store
- `folder`: folder path/prefix
- `envelope`: local envelope file path (CLI) or file-vault object id/path (API)

## 3. Security and Enforcement Model

Every share operation is deny-first and requires all checks to pass:
- RBAC scope check
- entitlement scope check
- ACL/resource policy check

Common required scopes:
- `share:create`
- `share:read`
- `share:revoke`
- `share:accept`
- `share:export`

Notes:
- Missing scope metadata is deny.
- Unauthorized attempts are audited.
- Export/transfer paths enforce creator ownership.

## 4. Share Lifecycle

1. `create`: create share record, optional recipient binding and limits.
2. `accept`: validates share state and records access.
3. `export`: creates encrypted offline package (`json`).
4. `import`: decrypts offline package with recipient encryption private key.
5. `revoke`: creator-only revocation.

State checks during `accept`:
- revoked -> deny
- expired -> deny
- one-time already used -> deny
- max access exceeded -> deny
- recipient mismatch -> deny

## 5. Offline Package Crypto

Offline packages use per-package DEK and X25519 key agreement:
- package data encrypted with random DEK
- DEK encrypted via X25519 shared secret (recipient key + ephemeral sender key)
- package includes ephemeral public key prefix for recipient-side key derivation
- package hash/integrity checked on import

## 6. Required vs Optional Flags Matrix

### `secretr share`

| Flag | Required | Type | Description |
|---|---|---|---|
| none | - | - | command group only |

### `secretr share create`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--type` | yes | `string` | `secret|file|folder|object|envelope` |
| `--resource`, `-r` | yes | `string` | resource key/path/id |
| `--recipient` | no | `string` | recipient identity ID |
| `--expires-in` | no | `duration` | share expiry duration |
| `--max-access` | no | `int` | max successful accepts |
| `--one-time` | no | `bool` | allow single accept only |

### `secretr share list`

| Flag | Required | Type | Description |
|---|---|---|---|
| none | - | - | list shares created by current identity |

### `secretr share revoke`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | yes | `string` | share ID |

### `secretr share accept`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | yes | `string` | share ID |

### `secretr share export`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | yes | `string` | share ID |
| `--output`, `-o` | yes | `string` | output package path |

### `secretr share import`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--input`, `-i` | yes | `string` | input package JSON file |
| `--output`, `-o` | no | `string` | write imported raw payload to file |
| `--password` | no | `string` | recipient password; prompts if omitted |

### `secretr share qr-generate`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | yes | `string` | share ID |
| `--api-url` | no | `string` | base API URL to encode |
| `--output`, `-o` | no | `string` | png output path (requires `qrencode`) |

### `secretr share qr-decode`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--input`, `-i` | yes | `string` | QR image input (requires `zbarimg`) |

### `secretr share lan-send`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | yes | `string` | share ID |
| `--bind` | no | `string` | listen address, default `0.0.0.0:8787` |
| `--api-url` | no | `string` | advertised URL override |
| `--ttl` | no | `duration` | wait/server lifetime, default `10m` |
| `--qr` | no | `bool` | print QR to terminal if `qrencode` exists |

### `secretr share lan-receive`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--url` | yes | `string` | sender package URL |
| `--output`, `-o` | no | `string` | write imported raw payload |
| `--password` | no | `string` | recipient password; prompts if omitted |

### `secretr share webrtc-offer`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--id` | conditional | `string` | existing share ID |
| `--type` | conditional | `string` | required if `--id` omitted |
| `--resource` | conditional | `string` | required if `--id` omitted |
| `--recipient` | conditional | `string` | required if `--id` omitted |
| `--bind` | no | `string` | signaling listener, default `0.0.0.0:8789` |
| `--api-url` | no | `string` | advertised base URL override |
| `--ttl` | no | `duration` | signaling endpoint lifetime, default `10m` |
| `--qr` | no | `bool` | print receiver URL as QR |
| `--stun` | no | `string` | STUN server URL |
| `--timeout` | no | `duration` | handshake/transfer timeout |

Conditional rule:
- either `--id`
- or all of `--type --resource --recipient`

### `secretr share webrtc-answer`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--url` | yes | `string` | sender URL from `webrtc-offer` output |
| `--output`, `-o` | no | `string` | write imported raw payload |
| `--password` | no | `string` | recipient password; prompts if omitted |
| `--stun` | no | `string` | STUN server URL |
| `--timeout` | no | `duration` | handshake/transfer timeout |

## 7. Positional Arguments Matrix

All `share` subcommands currently use flags only.

| Command | Required Positional Args | Optional Positional Args |
|---|---|---|
| `secretr share` | none | none |
| `secretr share create` | none | none |
| `secretr share list` | none | none |
| `secretr share revoke` | none | none |
| `secretr share accept` | none | none |
| `secretr share export` | none | none |
| `secretr share import` | none | none |
| `secretr share qr-generate` | none | none |
| `secretr share qr-decode` | none | none |
| `secretr share lan-send` | none | none |
| `secretr share lan-receive` | none | none |
| `secretr share webrtc-offer` | none | none |
| `secretr share webrtc-answer` | none | none |

## 8. Copy-Paste Use Cases

### A) Create + list + accept + revoke

```bash
secretr share create --type secret --resource general:ENCRYPTED_SECRET --recipient <RECIPIENT_ID> --expires-in 24h --max-access 3
secretr share list
secretr share accept --id <SHARE_ID>
secretr share revoke --id <SHARE_ID>
```

### B) Offline package export/import

Sender:
```bash
secretr share export --id <SHARE_ID> --output ./share-package.json
```

Receiver:
```bash
secretr share import --input ./share-package.json --output ./imported.bin
```

### C) LAN transfer (no central server)

Sender:
```bash
secretr share lan-send --id <SHARE_ID> --bind 0.0.0.0:8787 --qr
```

Receiver:
```bash
secretr share lan-receive --url http://<SENDER_LAN_IP>:8787/package/<PACKAGE_ID> --output ./received.bin
```

### D) Automatic WebRTC with existing share

Sender:
```bash
secretr share webrtc-offer --id <SHARE_ID> --bind 0.0.0.0:8789 --qr
```

Receiver:
```bash
secretr share webrtc-answer --url http://<SENDER_LAN_IP>:8789/webrtc/<TOKEN> --output ./received.bin
```

### E) Automatic WebRTC create+send in one command (secret/object/envelope)

Secret:
```bash
secretr share webrtc-offer --type secret --resource general:ENCRYPTED_SECRET --recipient <RECIPIENT_ID> --bind 0.0.0.0:8789 --qr
```

Object:
```bash
secretr share webrtc-offer --type object --resource <OBJECT_PATH_OR_ID> --recipient <RECIPIENT_ID> --bind 0.0.0.0:8789
```

Envelope:
```bash
secretr share webrtc-offer --type envelope --resource /path/to/envelope.json --recipient <RECIPIENT_ID> --bind 0.0.0.0:8789
```

## 9. API Parity

Current REST routes:
- `GET /api/v1/shares`
- `POST /api/v1/shares`
- `POST /api/v1/shares/accept/{id}`
- `POST /api/v1/shares/revoke/{id}`
- `GET /api/v1/shares/export/{id}`
- `POST /api/v1/shares/import`

Behavior highlights:
- share create validates resource type/id
- export enforces creator ownership
- import accepts package JSON/base64 and decrypts with recipient key
- folder resource export supported via archive generation

## 10. Troubleshooting

`recipient public key is required`:
- ensure recipient identity has encryption key metadata/public key.

`ACL denied`:
- check resource ownership, ACL grants, and route/command scope mapping.

`entitlement_scope_required`:
- license entitlements must include matching `share:*` scopes.

`timeout waiting for receiver answer`:
- verify receiver can access sender URL and both peers can establish ICE path.

`zbarimg binary not found` / `qrencode binary not found`:
- install the OS packages or avoid QR subcommands.

## 11. Audit Coverage

Share operations emit:
- authz decision events (`allow`/`deny` with reason)
- CLI/API action audit events
- share access/revocation state changes in persistent stores

Use `audit` commands/API to inspect execution history and denials.

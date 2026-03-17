# Secretr API Reference

This file is auto-generated from live route registration.
Do not edit manually. Regenerate with:

```bash
go run ./internal/secretr/cmd/genapidocs
```

## Common Notes
- Base URL: `http://127.0.0.1:9090`
- Auth header: `Authorization: Bearer <session_id>`
- Routes with `AllowUnauth=true` do not require a session token.
- Command dispatch endpoint: `POST /api/v1/commands/<cli path as slashes>`

## GET /api/v1/alerts

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/alerts \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/alerts/id

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/alerts/id \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/alerts/id/acknowledge

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/alerts/id/acknowledge \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## GET /api/v1/alerts/notifiers

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/alerts/notifiers \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/alerts/rules

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/alerts/rules \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/alerts/rules

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/alerts/rules \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## GET /api/v1/audit

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:query` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/audit \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/audit/export

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:export` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/audit/export \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/auth/login

| Property | Value |
|---|---|
| AllowUnauth | `true` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `-` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## POST /api/v1/auth/logout

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `auth:logout` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/auth/logout \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## POST /api/v1/auth/refresh

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `auth:login` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/auth/refresh \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## POST /api/v1/cicd/auth

| Property | Value |
|---|---|
| AllowUnauth | `true` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `pipeline:auth` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/cicd/auth \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## POST /api/v1/commands/auth/login

| Property | Value |
|---|---|
| AllowUnauth | `true` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `-` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/commands/auth/login \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## POST /api/v1/commands/secret/list

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `admin:*` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/commands/secret/list \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## GET /api/v1/files

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `file` |
| RequiredScopes | `file:list` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/files \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/files

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `file` |
| RequiredScopes | `file:upload` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/files \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## DELETE /api/v1/files/name

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `file` |
| RequiredScopes | `file:delete` |

Copy-paste example:

```bash
curl -i -X DELETE http://127.0.0.1:9090/api/v1/files/name \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/files/name

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `file` |
| RequiredScopes | `file:download` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/files/name \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/identities

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `identity` |
| RequiredScopes | `identity:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/identities \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/identities/id

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `identity` |
| RequiredScopes | `identity:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/identities/id \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/monitoring/dashboard

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/monitoring/dashboard \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/monitoring/dashboard

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/monitoring/dashboard \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## GET /api/v1/monitoring/events

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/monitoring/events \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/monitoring/stream

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `audit` |
| RequiredScopes | `audit:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/monitoring/stream \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/secrets

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `secret` |
| RequiredScopes | `secret:list` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/secrets \
  -H 'Authorization: Bearer <session_id>'
```

## POST /api/v1/secrets

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `secret` |
| RequiredScopes | `secret:create` |

Copy-paste example:

```bash
curl -i -X POST http://127.0.0.1:9090/api/v1/secrets \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## DELETE /api/v1/secrets/name

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `secret` |
| RequiredScopes | `secret:delete` |

Copy-paste example:

```bash
curl -i -X DELETE http://127.0.0.1:9090/api/v1/secrets/name \
  -H 'Authorization: Bearer <session_id>'
```

## GET /api/v1/secrets/name

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `secret` |
| RequiredScopes | `secret:read` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/api/v1/secrets/name \
  -H 'Authorization: Bearer <session_id>'
```

## PUT /api/v1/secrets/name

| Property | Value |
|---|---|
| AllowUnauth | `false` |
| RequireACL | `true` |
| ResourceType | `secret` |
| RequiredScopes | `secret:update` |

Copy-paste example:

```bash
curl -i -X PUT http://127.0.0.1:9090/api/v1/secrets/name \
  -H 'Authorization: Bearer <session_id>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## GET /health

| Property | Value |
|---|---|
| AllowUnauth | `true` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `-` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/health
```

## GET /ready

| Property | Value |
|---|---|
| AllowUnauth | `true` |
| RequireACL | `false` |
| ResourceType | `-` |
| RequiredScopes | `-` |

Copy-paste example:

```bash
curl -i -X GET http://127.0.0.1:9090/ready
```


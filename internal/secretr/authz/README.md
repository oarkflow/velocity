# Secretr Authz

Central deny-first authorization is enforced for CLI and API operations in this order:

1. Active auth/session check
2. RBAC scope check
3. License entitlement check (`allow/deny/limit` + restrictions)
4. ACL resource check

All layers must pass.

## Scope format

Scopes use `domain:action` literals (example: `secret:read`) and must match
license entitlement `scope_slug` values exactly.

## Fail-closed behavior

- Missing CLI command/flag/arg spec: denied (`authz_spec_missing`)
- Missing API route+method spec: denied (`authz_spec_missing`)
- Missing entitlement scope/license: denied (`entitlement_scope_required`)

## CLI parity

`BuildCLIAuthSpecs(...)` inventories the runtime command tree and generates
command/flag/arg specs. Tests fail if any discovered command path or flag lacks
an auth spec.

## API parity

API auth specs are attached during route registration in `api/server.go`.
Route/method contracts are derived from the registered server inventory via
`RouteMethodContract()`, and tests fail if any route lacks auth metadata.

## Usage limits

Entitlement `limit` and `restrictions` are enforced through a `UsageCounter`.
Default is in-memory (`MemoryUsageCounter`); persistent option is
`StoreUsageCounter`.

## Adding new commands/routes

1. Add command or route.
2. Ensure scope mapping resolves (explicit map or inferable `domain:action`).
3. Run parity tests; missing metadata must fail.
4. Add/adjust tests for expected deny reason and error code.

## Manifest Generation

Regenerate command authorization manifests after adding/changing CLI commands:

```bash
go run ./internal/secretr/authz/cmd/genmanifests
```

This updates:
- `internal/secretr/authz/command_scope_manifest.json`
- `internal/secretr/authz/command_surface_manifest.json`

A sync test (`manifest_sync_test.go`) fails if checked-in manifests drift from generated output.

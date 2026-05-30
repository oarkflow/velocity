# Security

## Cryptography

Velocity includes a crypto provider for encrypted persistence and helpers for FIPS-oriented modes. Tests cover encryption/decryption, wrong-key rejection, PBKDF2, Argon2id, salt generation, secure zeroing, and FIPS validation helpers.

Production-sensitive benchmark flags exist:

- `DisableEncryption`
- `DisableWAL`
- `DisableFsync`
- `DisableIndexPersistence`
- `SkipCloseFlush`

These are for benchmarks or specialized testing and should not be enabled for production safety.

## Master Keys

Master key management supports:

- System-file keys.
- User-defined keys.
- Existing-key detection.
- Key cache expiry.
- Cache clearing.
- Shamir share workflows and automatic share usage.
- HTTP admin routes for master key config, refresh, and cache status.

Admin routes require a JWT with `role=admin`.

## Authentication And Authorization

HTTP APIs use JWT bearer auth after `POST /auth/login`. Tokens require a non-empty `username` claim and a `role` of `user` or `admin`.

Additional security subsystems include:

- RBAC roles and permissions in `pkg/auth`.
- IAM policy engine in `pkg/auth`.
- STS temporary credentials.
- OIDC provider.
- LDAP provider.
- MFA manager with TOTP/HOTP and backup codes in `pkg/auth`.
- Break-glass manager.
- Segregation of duties manager in `pkg/auth`.
- Access reviews in `pkg/auth`.

Go:

```go
import "github.com/oarkflow/velocity/pkg/auth"

rbac := auth.NewRBACManager(db)
iam := auth.NewIAMPolicyEngine(db)
mfa := auth.NewMFAManager(db)
_ = rbac
_ = iam
_ = mfa
```

## Object Access

Objects support ACLs, owners, public access flags, permission checks, versioned metadata, hard delete, object lock, retention checks, checksum validation, and repair.

S3 endpoints use SigV4-style auth middleware and credential storage. Tests cover credential handling, SigV4 parsing, presigned URL generation, and tamper rejection.

## Secrets

The minimal CLI stores secrets as ordinary encrypted KV values under `secret:general:<name>`.

The hardened secret subsystem supports structured secret records, sealed values, rotation, retrieval, and envelope reference validation.

## Audit And Integrity

Security-relevant audit features include:

- Immutable audit log manager.
- Backup HMAC/signature verification.
- Audit trail export.
- Audit chain verification.
- Forensic export structures.
- Tampering indicators.
- Object integrity manager.
- Bit rot detector and healing manager.

## Test-Backed Security Caveats

The repo contains pentest-style tests in `pkg/web/pentest_security_test.go` that identify high-risk behaviors such as default JWT secret concerns, object version enumeration/IDOR risks, ACL update IDOR risks, route shadowing concerns, missing username claim handling, and search abuse surfaces. Treat [Limitations](LIMITATIONS.md) as required reading before exposing the server in a hostile environment.

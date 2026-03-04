# TLS/mTLS Deployment Baseline

## Minimum Requirements
- TLS 1.2+ (prefer TLS 1.3)
- Strong cipher suites only
- HSTS enabled for HTTP interfaces
- Certificate rotation every 90 days (or shorter)

## mTLS Policy
- Enforce mTLS for service-to-service traffic.
- Separate client cert CAs by environment.
- Reject unknown SAN/CN identities.

## Verification
- [ ] TLS config linted in staging.
- [ ] mTLS handshake validated for all internal clients.
- [ ] Expiring cert alert configured.


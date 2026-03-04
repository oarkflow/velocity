# Network Policy Baseline

## Ingress
- Allow only API and health endpoints from approved CIDRs.
- Restrict admin interfaces to bastion/VPN source ranges.

## Egress
- Allowlist only required destinations:
  - OIDC JWKS providers
  - notification providers (webhook/slack/pagerduty/smtp)
  - artifact/backup storage

## Segmentation
- Separate policy for control-plane and data-plane services.
- Deny all by default; explicit allow rules only.

## Verification
- [ ] Policy-as-code committed and reviewed.
- [ ] Staging connectivity matrix validated.
- [ ] Unauthorized flow tests fail as expected.


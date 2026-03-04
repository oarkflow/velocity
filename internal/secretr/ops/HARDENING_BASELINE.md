# Hardening Baseline

## Host/Runtime
- [ ] Minimal OS image and patched kernel/userspace.
- [ ] Non-root runtime, read-only FS where feasible.
- [ ] Mandatory seccomp/apparmor/selinux profile.
- [ ] Time sync and secure entropy source.

## Application
- [ ] Strict input validation and fail-closed auth checks.
- [ ] Encrypted-at-rest and encrypted-in-transit enforced.
- [ ] Rate limiting and abuse detection configured.
- [ ] Audit retention and tamper-evidence validation enabled.

## Secrets and Keys
- [ ] Master key handling policy approved.
- [ ] Key rotation schedule documented and active.
- [ ] Secret zeroization controls verified in tests.


# Staging Runbook and Rollback Validation

## Objective
Validate Secretr release in staging and prove rollback safety.

## Pre-Checks
- [ ] Build artifacts signed and versioned.
- [ ] DB snapshot/backup taken.
- [ ] Feature flags/defaults documented.

## Staging Execution
1. Deploy new Secretr build.
2. Run smoke suite:
   - auth/login/session
   - secret create/get/rotate/export
   - file upload/download/protect/kill/revive
   - audit export/verify
   - cicd oidc auth
3. Run integration and compatibility tests.

## Rollback Drill
1. Trigger rollback to previous known-good release.
2. Restore compatible config and validate service health.
3. Re-run smoke suite on rolled back version.

## Evidence
- [ ] Deployment logs
- [ ] Smoke test output
- [ ] Rollback command logs
- [ ] Post-rollback health confirmation

## Result
- Status: `PASS` / `FAIL`
- Owner:
- Date:


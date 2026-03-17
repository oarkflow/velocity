# Secret Rotation Runbook

## Routine Rotation
1. Identify scope (org/env/resource class).
2. Trigger rotation:
   - `secretr secret rotate --name ...`
   - or batch workflow via pipeline/incident tooling.
3. Validate downstream systems consume new values.
4. Revoke old credentials and confirm no stale usage.

## Emergency Rotation
1. Declare incident and freeze if needed.
2. Rotate all impacted secrets (`secretr incident rotate --all`).
3. Force session/token invalidation.
4. Verify access logs and alert stream for residual use.

## Evidence
- [ ] Rotation ticket ID
- [ ] Actor/approver IDs
- [ ] Start/end timestamps
- [ ] Validation output


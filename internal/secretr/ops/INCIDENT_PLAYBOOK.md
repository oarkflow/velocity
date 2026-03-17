# Secretr Incident Response Playbook

## Severity Model
- `critical`: active compromise, data exposure, or key compromise.
- `high`: attempted compromise or control bypass with high confidence.
- `medium`: suspicious behavior requiring containment.
- `low`: policy drift or low-confidence anomaly.

## Response Workflow
1. Declare incident: `secretr incident declare ...`
2. Contain:
   - `secretr incident freeze`
   - disable affected CI/CD pipelines.
3. Rotate:
   - `secretr incident rotate --all` or targeted names.
4. Preserve evidence:
   - `secretr incident export --id ... --output ...`
   - `secretr audit export --output ...`
5. Recover:
   - restore authorized access gradually.
   - verify audit chain integrity.
6. Postmortem:
   - root cause, blast radius, and control updates.

## Communication Matrix
- Incident Commander: Security Lead
- Operations Lead: Platform/Infra Lead
- Engineering Lead: Secretr Maintainer
- Compliance/Legal: Compliance Officer

## Exit Criteria
- Compromise path closed.
- Rotations complete and validated.
- Evidence archived and immutable.
- Postmortem approved with follow-up actions.


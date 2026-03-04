# Audit Integrity Validation Procedure

1. Export audit chain proof from audit subsystem.
2. Verify chain and merkle proofs via audit verify command/API.
3. Compare latest block hash with previously notarized hash (if used).
4. Record validation timestamp, actor, and result artifact.

## Checklist
- [ ] Chain verification passed
- [ ] Proof verification passed
- [ ] Export signature verified
- [ ] Evidence archived


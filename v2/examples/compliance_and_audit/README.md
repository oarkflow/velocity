# compliance_and_audit

Demonstrates Velocity v2's `compliance` plugin end to end: a hash-chained,
tamper-evident audit trail; data classification/residency/lineage
tracking; configurable masking strategies (full/partial/redact); rule-pack
import that changes policy outcomes at runtime; queryable violation
tracking; and break-glass emergency access with structurally enforced
segregation of duties (an approver can never approve their own request).

## Run

```sh
go run ./examples/compliance_and_audit
```

## Expected output summary

- Audit chain verifies intact after 3 recorded events.
- A residency rule allows the matching region and rejects a different one,
  with a human-readable reason.
- Lineage events are returned in the order recorded.
- The same plaintext masked three ways produces three visibly different
  outputs.
- A rule pack import flips a previously-allowed action to denied, and the
  denial is recorded as a queryable `Violation`.
- Break-glass access succeeds with a distinct approver and is rejected
  when the requestor and approver are the same person.

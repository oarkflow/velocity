# Envelope Secure Auditing Example

This example demonstrates a practical envelope flow with secured auditing coverage:

- Access-chain logging
- Dependency logging
- Custody-chain logging
- Event logging
- Recipient-only access enforcement

## 1) Create recipient-only envelope

```bash
secretr envelope create \
  --recipient "recipient-secure" \
  --secret "ENV_SECRET:vault-secret" \
  --file "./evidence/incident.txt" \
  --message "recipient-only secure payload" \
  --policy "policy-prod-envelope" \
  --require-mfa \
  --expires-in 2h \
  --output "./out/secure-envelope.json"
```

## 2) Verify chain before open

```bash
secretr envelope verify --file "./out/secure-envelope.json"
```

## 3) Recipient opens envelope

```bash
secretr envelope open --file "./out/secure-envelope.json"
```

Expected behavior:

- Open succeeds only for `recipient-secure`
- Envelope signature and custody-chain integrity are validated
- CLI emits envelope audit events including:
  - `envelope_open`
  - `envelope_access_chain`
  - `envelope_dependency_chain`
  - `envelope_custody_chain`
  - `envelope_event_log`

## 4) Inspect custody chain

```bash
secretr envelope open --file "./out/secure-envelope.json" --inspect
```

## 5) Query audit logs for the envelope

```bash
secretr audit query --action "envelope_open" --limit 50
secretr audit query --action "envelope_access_chain" --limit 50
secretr audit query --action "envelope_dependency_chain" --limit 50
secretr audit query --action "envelope_custody_chain" --limit 50
secretr audit query --action "envelope_event_log" --limit 50
```

## 6) Export signed audit evidence package

```bash
secretr audit export --output "./out/envelope-audit-export.json"
secretr audit verify
```

## Notes

- Envelope custody entries now include structured fields for stronger forensic use:
  - `prev_hash`, `category`, `outcome`, `related`, `details`
- Dependency references include policy, secret names, and file names from payload metadata.

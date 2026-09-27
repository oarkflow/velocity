# envelope_custody

Demonstrates Velocity v2's `envelope` plugin — v1's "secure evidence
cabinet" concept: a sealed container with an append-only, hash-chained
chain-of-custody ledger, tamper-evident export/import, and bundle
envelopes that reference content stored elsewhere (kv keys, inline bytes)
rather than copying it in.

## Run

```sh
go run ./examples/envelope_custody
```

## Expected output summary

- Creating an envelope seeds a 1-entry custody chain; each
  `AppendCustodyEvent` call extends it, and each entry's `PrevHash` links
  to the previous entry's `EventHash`.
- `Get` correctly unseals the stored content back to its original bytes.
- `Export` then `Import` reproduces the envelope, including its full
  custody history.
- An exported stream with one flipped bit is rejected by `Import` with an
  authentication-failure error — it never silently succeeds.
- A `Kind: "bundle"` envelope resolves its referenced `kv` and `inline`
  resources on demand via `ResolveResources`, without having copied their
  content into the envelope itself.

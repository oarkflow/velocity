# erasure_resilience

Demonstrates Velocity v2's erasure-coded shard store: store a payload,
simulate real bit-rot by corrupting one underlying shard directly on disk
(bypassing the plugin), then show the corruption is detected, transparently
tolerated on read (parity reconstructs the correct original data), and
finally repaired in place via `HealShards`.

Run:

```sh
go run ./examples/erasure_resilience
```

Expected output: `VerifyShards` reports healthy, then corrupt after the
simulated bit-rot, `ReadShards` still returns the exact original bytes
despite the corruption, and a final `VerifyShards` after `HealShards`
reports healthy again.

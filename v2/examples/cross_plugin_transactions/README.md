# cross_plugin_transactions

Demonstrates `api.TxCoordinator`/`api.CrossTx` (`plugins/transaction`): a single
`Commit` atomically applies writes staged by **different** plugins (`kv` and
`secret`), because both resolve to the same underlying storage instance.

Shows: staging a `kv.PutStaged` + `secret.SetStaged` write and committing them
together (both take effect); staging then `Rollback`ing instead (neither takes
effect); and `Stage` refusing a second, genuinely different `StorageBackend`
instance rather than silently combining it. The deeper "a mid-batch failure
leaves nothing applied" guarantee is proven in
`plugins/transaction/integration_test.go`'s
`TestCrossPluginTx_GenuineAtomicityUnderPartialFailure` — not reproduced here
since it needs a deliberately-poisoned backend, impractical against a real,
unmodified `storage-lsm` instance.

Run: `go run ./examples/cross_plugin_transactions`

# kv_basic

Demonstrates Velocity v2's key-value surface (`api.KVService`) by booting
the microkernel with `storage-lsm` + `kv` directly in Go code — no CLI, no
running server, just embedding the library.

Covers: `Put`/`Get`, `PutWithTTL` (with real expiry), `Exists`, `Incr`,
`Delete`, `Keys` (glob), and paginated `Scan` (cursor advancing across
pages).

## Run

```sh
go run ./examples/kv_basic
```

Uses a temp directory for storage, cleaned up automatically on exit. No
setup required.

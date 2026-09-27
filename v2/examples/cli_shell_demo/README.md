# CLI shell demo

`run.sh` demonstrates every real subcommand of the Velocity v2 embedded CLI
(`v2/cmd/velocity`): `kv put/get/delete`, `secret set/get`,
`object put/get/list`, `compliance audit-verify`, and `search index/query`.

The CLI is embedded, not a client talking to a server: each invocation
boots the kernel, runs one command, and shuts down again. This script
builds the CLI once into a temp binary, writes a throwaway manifest
(enabling only `storage-lsm`, `crypto-xchacha`, `kv`, `object`, `secret`,
`compliance`, and `search`) pointed at a temp data directory, then walks
through every command in a logical order, checking each result.

## Run it

```sh
bash examples/cli_shell_demo/run.sh   # from the v2 module root
# or
./run.sh                              # from this directory
```

It resolves its own location, so it works from either place. Everything
(temp binary, manifest, data directory) is cleaned up on exit via a
`trap`.

## Expected output

A banner per step (`=== kv put ===`, etc.), the command's real output,
and an `OK: ...` confirmation line — ending with:

```
All CLI commands demonstrated successfully.
```

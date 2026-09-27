# full_server

The flagship Velocity v2 example: boots a server-shaped subset of the
plugin set (storage-lsm, crypto-xchacha, kv, object, secret, auth-jwt,
compliance, metrics, web) in one process, then drives the real HTTP API
with actual `net/http` requests — issuing a JWT, doing authenticated KV
and object PUT/GET round trips, and fetching real Prometheus metrics.

## Run

```sh
go run ./examples/full_server
```

## Expected output

Boots 9 plugins, issues a JWT for `demo-user`/`admin`, then shows five
live HTTP round trips (KV put/get, bucket create, object put/get) each
returning the expected status code and body, followed by real
`# HELP`/`# TYPE` Prometheus output from `/metrics`, then a clean
shutdown.

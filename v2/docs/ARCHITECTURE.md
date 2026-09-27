# Velocity v2 Architecture

Velocity v2 is a full plugin/microkernel rework of the v1 storage engine
(which stays untouched at the repo root — v2 lives entirely under `v2/` as
its own Go module, `github.com/oarkflow/velocity/v2`). This document is
the developer reference for how the pieces fit together and how to extend
the system. It is written to correct, not repeat, any past overselling —
see section (f) for what this explicitly does not solve.

## (a) The microkernel model

The kernel (`v2/kernel`) does exactly four things and nothing else:

1. **Plugin lifecycle** — dependency-ordered `Init`/`Start`, reverse-order `Stop`.
2. **Service discovery** — a `Registry` plugins use to publish what they provide and look up what they depend on.
3. **Cross-cutting events** — an `EventBus` plugins publish to and subscribe on.
4. **Scoped config + logging** — handed to every plugin via the `Kernel` facade.

The kernel has **zero knowledge** of KV, object storage, secrets, crypto,
auth, compliance, replication, SQL, search, or the web/S3 gateway. Every
one of those is a `Plugin` living under `v2/plugins/*`, built against the
interfaces in `v2/api`. If you deleted every directory under
`v2/plugins`, the kernel would still compile and still boot — it would
just have nothing to boot.

This inverts v1's structure, where one `DB` type in the root package
directly held storage, crypto, compliance, and replication logic all
coupled together (the single biggest structural complaint from the v1
audit that motivated this rework). In v2, nothing is coupled to anything
else except through the two narrow mechanisms below: the `Registry` and
the `EventBus`.

## (b) The Plugin interface and boot algorithm

Every plugin implements `api.Plugin`:

```go
type Plugin interface {
    Name() string
    Version() string
    Dependencies() []string
    Init(ctx context.Context, k Kernel) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Health() Health
}
```

`Dependencies()` returns the `Name()`s of other plugins that must be
`Init`'d before this one. `Kernel.Boot(ctx, allPlugins, enabled)` does a
topological sort restricted to the plugins listed in `enabled` (i.e. the
manifest — see (e)), then:

1. Calls `Init` on every plugin, in dependency order.
2. Calls `Start` on every plugin, in the same order.

A dependency cycle, a plugin enabled without an enabled dependency, or any
`Init`/`Start` error aborts the whole boot — there is no partially-started
kernel left running in an inconsistent state. `Kernel.Shutdown` calls
`Stop` on every booted plugin in **reverse** order.

`Init` is where a plugin does its wiring — look up dependencies, register
what it provides, subscribe to events. `Init` must not start background
work; that's `Start`'s job, so that by the time any plugin's `Start` runs,
every plugin (including plugins that come later in dependency order) has
already finished `Init` and is reachable via the registry.

## (c) Two namespaces: service names vs. plugin names

This is the detail that makes backends swappable without touching
consumers, so it's worth being explicit about.

**Plugin `Name()`** is used *only* for dependency-graph ordering during
boot. Every plugin currently in the tree:

```
storage-lsm  storage-mem  kv  object  secret
crypto-xchacha  crypto-fips
auth-jwt  auth-ldap  auth-oidc  auth-sts
compliance  replication  sql  search  web  metrics
```

**Service name** is a separate, fixed string a plugin registers its
capability under via `Registry.Provide(name, svc)`, and that any other
plugin looks up via `Registry.Lookup(name)` (or `MustLookup`, after
dependency ordering guarantees it's there). The fixed service names in
use:

| Service name | Interface | Provided by (one of) |
|---|---|---|
| `storage` | `api.StorageBackend` | `storage-lsm` **or** `storage-mem` |
| `kv` | `api.KVService` | `kv` |
| `object` | `api.ObjectService` | `object` |
| `secret` | `api.SecretService` | `secret` |
| `crypto` | `api.CryptoProvider` | `crypto-xchacha` **or** `crypto-fips` |
| `keyprovider` | `api.KeyProvider` | (part of `secret`'s Shamir-backed master key manager) |
| `auth.jwt` | `api.AuthProvider` | `auth-jwt` |
| `auth.ldap` | `api.AuthProvider` | `auth-ldap` |
| `auth.oidc` | `api.AuthProvider` | `auth-oidc` |
| `auth.sts` | `api.AuthProvider` | `auth-sts` |
| `compliance` | `api.ComplianceService` | `compliance` |
| `cluster` | `api.ClusterMembership` | `replication` |
| `replication.transport` | `api.ReplicationTransport` | `replication` |
| `sql` | `api.SQLEngine` | `sql` |
| `search.fulltext` | `api.SearchIndex` | `search` |
| `search.vector` | `api.VectorIndex` | `search` |
| `search.graph` | `api.GraphStore` | `search` |
| `metrics` | `api.MetricsSink` | `metrics` |

**Why two namespaces?** A consumer plugin's `Dependencies()` names a
*specific concrete plugin* for boot ordering (e.g. `kv`'s constructor
takes a `storageDep` parameter, defaulting to `"storage-lsm"`), but at
runtime it always does `Registry.MustLookup("storage")` — the fixed
service name — to get the actual `api.StorageBackend`. Swapping the
backend is then purely a manifest + constructor-argument change:

```go
kv.New("storage-mem")   // instead of kv.New("storage-lsm")
```

and flip the two `enabled` flags in the manifest. `kv`'s code never
changes, because it was never looking up `"storage-lsm"` by name — it was
always looking up `"storage"`.

## (d) The event bus decouples cross-cutting concerns

Compliance and replication are the worked example. Neither `kv` nor
`object` imports `compliance` or `replication`, and neither knows they
exist. Instead:

- `kv` and `object` publish `api.Event{Topic: api.TopicKVPut, ...}` (and
  `TopicKVDelete`/`TopicObjectPut`/`TopicObjectDelete`) via
  `k.Events().Publish` on every mutation.
- `compliance`, in its own `Init`, calls `k.Events().Subscribe(api.TopicKVPut, handler)`
  (and the other topics) and records an audit event for each one it
  observes.
- `replication` can do the same thing to fan mutations out to other
  cluster nodes.

Because this is pub/sub rather than a direct call, **removing `compliance`
from the manifest entirely removes audit logging with zero code changes
anywhere else** — `kv`/`object` keep publishing events into a bus nobody
is listening to, which is a no-op. The reverse is also true: adding a new
observer plugin (say, a webhook-notification plugin) never requires
touching `kv`/`object`/`compliance`/`replication` — just subscribe to the
same topics.

`EventBus.Publish` is synchronous with per-handler panic recovery: a
misbehaving observer can't take down the publisher or other observers, but
a slow handler does delay the publish call, so handlers that need to do
real work should hand it off to a goroutine/queue internally rather than
blocking.

## (e) How to add a new plugin

This is the entire extension surface — it is what "flexible and
extensible" concretely means for this rework:

1. Implement `api.Plugin` (`Name`/`Version`/`Dependencies`/`Init`/`Start`/`Stop`/`Health`).
2. If it provides a capability other plugins should be able to use,
   implement the matching service interface from `v2/api` (or define a new
   one if it's a genuinely new capability) and `Registry.Provide` it under
   a service name, following the table in (c).
3. If it needs to observe what other plugins do, `Registry.Lookup` their
   service (for a direct call) or `Events().Subscribe` their topics (for
   an observer relationship, per (d)) — prefer subscribe unless you
   genuinely need a synchronous return value.
4. Construct it in `cmd/velocityd/main.go`'s `allPlugins()`.
5. Add an entry for it to a manifest (`v2/config/velocityd.example.json`
   or your own), with `"enabled": true` and whatever config it reads via
   `k.Config().Scoped(pluginName)`.

That's it. No kernel change, no change to any other plugin. A minimal
deployment (see `v2/config/velocityd.minimal.json`, which enables only
`storage-mem` + `kv`) and a full one (`velocityd.example.json`, enabling
everything currently built) are both just different manifests against the
exact same binary.

## (f) What this deliberately does not solve

`replication` provides gossip-style cluster membership, consistent-hash
key routing, and best-effort asynchronous, **eventually-consistent**
replication — the same honest scope v1 had. There is **no
consensus/quorum protocol** (no Raft, no Paxos) anywhere in this rework,
and adding one was explicitly out of scope for this pass. Do not describe
this system as providing linearizable multi-node writes or as
"distributed fault-tolerant" without that caveat — a future consensus
layer, if built, would be its own plugin sitting on top of
`ClusterMembership`/`ReplicationTransport`, not a kernel change.

Similarly, `auth-jwt` requires an explicit signing secret and refuses to
boot without one — this closes a critical finding from v1's own pentest
suite (a default JWT secret that allowed admin-token forgery) — but no
plugin in this tree has been through an independent security review;
treat everything here as a structural improvement over v1's specific
known issues, not a blanket security certification.

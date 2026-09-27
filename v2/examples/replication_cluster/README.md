# replication_cluster

Demonstrates Velocity v2's replication plugin: two nodes join a gossip
cluster (node B seeded from node A), membership converges on both sides,
consistent-hash key routing is stable, and a graceful `Leave` is reflected
in the remaining node's membership view.

Run:

```sh
go run ./examples/replication_cluster
```

Expected output: both nodes report seeing 2 members, a sample key routes
to the same node across repeated calls, and after node B leaves, node A's
view drops back to 1 member. This is gossip-style membership and routing
only — no consensus/quorum writes, stated explicitly in the output.

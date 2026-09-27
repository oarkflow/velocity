# raft_cluster

Demonstrates Velocity v2's real Raft consensus (`api.RaftService`,
`plugins/raft`): a genuine 3-node cluster with leader election, quorum-
committed log replication, and automatic re-election on leader failure.

Boots 3 independent kernels (each its own `storage-lsm` instance + the
`raft` plugin, with a simple in-memory `api.RaftFSM` that records applied
entries), waits for a real leader election, proposes entries and confirms
all 3 nodes applied them in the same order, then kills the leader's kernel
and confirms the 2 survivors elect a new leader and keep working — with the
pre-failover entries preserved.

**Scope, stated honestly**: this is core Raft (election + replication +
majority commit) over a **fixed** peer set — no membership changes, no log
compaction/snapshotting yet. See `plugins/raft`'s package doc comment.

Run: `go run ./examples/raft_cluster` (takes a few seconds; bounded timeouts
throughout, so it never hangs — if election doesn't converge within 5s it
fails loudly instead).

// Package replication provides the "replication" v2 plugin: cluster
// membership (gossip-style, over a length-framed TCP transport) and
// best-effort asynchronous fan-out replication of kv/object mutations to
// other cluster members, ported from v1's cluster.go, wire_protocol.go,
// replication.go/bucket_replication.go, loadbalancer.go, and pkg/core's
// consistent-hash ring.
//
// Scope note (deliberately honest, matching v1): this package implements
// gossip-style membership and consistent-hash routing. It does NOT
// implement a consensus protocol (no Raft/Paxos/quorum writes) — v1 never
// had one either. Replication here is eventually consistent and
// best-effort: a write can succeed locally and still fail to reach a peer
// (logged, not retried forever). Anything requiring linearizable
// multi-node writes needs a separate consensus layer on top of this; that
// is out of scope for this plugin.
package replication

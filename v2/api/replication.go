package api

import "context"

// NodeInfo describes one cluster member.
type NodeInfo struct {
	ID      string
	Address string
	State   string // "joining", "active", "leaving", "down"
}

// ClusterMembership is the node-discovery/routing surface, ported from
// v1's cluster.go + pkg/core's consistent-hash ring. As in v1, this is
// gossip-style membership and consistent-hash routing — it intentionally
// does NOT provide consensus/quorum writes. Anything requiring
// linearizable multi-node writes needs a separate consensus plugin layered
// on top; that is explicitly out of scope for v2's initial rework, same
// as it was unimplemented in v1.
type ClusterMembership interface {
	Join(ctx context.Context, seed string) error
	Leave(ctx context.Context) error
	Members() []NodeInfo
	NodeForKey(key []byte) NodeInfo
}

// ReplicationTransport is the wire-level send/receive surface used for
// async, eventually-consistent replication between nodes, ported from
// v1's wire_protocol.go.
type ReplicationTransport interface {
	Send(ctx context.Context, target NodeInfo, payload []byte) error
	OnReceive(handler func(from NodeInfo, payload []byte))
}

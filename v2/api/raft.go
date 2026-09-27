package api

import "context"

// RaftService exposes a crash-safe, quorum-committed replicated log
// (single-decree-per-entry Raft: leader election + log replication +
// commit-index advancement). Service name: "raft".
//
// Scope, stated explicitly: this covers the core Raft safety/liveness
// guarantees over a FIXED set of nodes configured at startup. It does
// NOT implement cluster membership changes (joint consensus), log
// compaction/snapshotting, or leader-request-forwarding beyond reporting
// the current leader's address — see plugins/raft's package doc comment.
type RaftService interface {
	// Propose submits data to the replicated log. It blocks until a
	// majority of nodes have durably persisted the entry and this node
	// has applied it via RaftFSM.Apply, or returns an error if this node
	// is not the leader (the error should let the caller discover the
	// current leader via Leader()) or ctx is done first.
	Propose(ctx context.Context, data []byte) error
	// IsLeader reports whether this node currently believes itself to be
	// the leader. Advisory only — Raft leadership can change at any time;
	// a true result can be stale by the time the caller acts on it.
	IsLeader() bool
	// Leader returns the node ID this node currently believes is leader,
	// if it knows of one.
	Leader() (nodeID string, ok bool)
}

// RaftFSM receives every committed log entry, in log order, exactly once
// per node. This is how data Propose'd on the leader takes effect on
// every node (e.g. applying it to an api.StorageBackend).
type RaftFSM interface {
	Apply(entry []byte) error
}

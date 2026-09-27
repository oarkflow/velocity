package raft

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// Durable Raft state, persisted via the looked-up api.StorageBackend so a
// restarting node never forgets its term/vote/log — a real correctness
// requirement of Raft (voting twice in the same term, or forgetting a
// committed log entry, after a restart can corrupt the whole cluster).
const (
	keyTerm     = "raft/state/term"
	keyVotedFor = "raft/state/votedfor"
	logPrefix   = "raft/log/"
)

// LogEntry is one entry in the replicated log.
type LogEntry struct {
	Term  int64  `json:"term"`
	Index int64  `json:"index"`
	Data  []byte `json:"data"`
}

func logKey(index int64) []byte {
	b := make([]byte, len(logPrefix)+8)
	copy(b, logPrefix)
	binary.BigEndian.PutUint64(b[len(logPrefix):], uint64(index))
	return b
}

func persistTerm(ctx context.Context, sb api.StorageBackend, term int64) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(term))
	return sb.Put(ctx, api.Entry{Key: []byte(keyTerm), Value: buf})
}

func loadTerm(ctx context.Context, sb api.StorageBackend) (int64, error) {
	v, ok, err := sb.Get(ctx, []byte(keyTerm))
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return int64(binary.BigEndian.Uint64(v)), nil
}

func persistVotedFor(ctx context.Context, sb api.StorageBackend, id string) error {
	return sb.Put(ctx, api.Entry{Key: []byte(keyVotedFor), Value: []byte(id)})
}

func loadVotedFor(ctx context.Context, sb api.StorageBackend) (string, error) {
	v, ok, err := sb.Get(ctx, []byte(keyVotedFor))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return string(v), nil
}

func persistLogEntry(ctx context.Context, sb api.StorageBackend, e LogEntry) error {
	v, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return sb.Put(ctx, api.Entry{Key: logKey(e.Index), Value: v})
}

// truncateLogFrom deletes every persisted entry at index >= from (used
// when a follower's log conflicts with the leader's and must be
// overwritten).
func truncateLogFrom(ctx context.Context, sb api.StorageBackend, from int64, upTo int64) error {
	var ops []api.BatchOp
	for i := from; i <= upTo; i++ {
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: logKey(i)}})
	}
	if len(ops) == 0 {
		return nil
	}
	return sb.Batch(ctx, ops)
}

// loadLog reconstructs the full in-memory log from persisted entries, in
// ascending index order (StorageBackend.Scan walks keys in ascending
// order, and logKey's big-endian index encoding sorts correctly).
func loadLog(ctx context.Context, sb api.StorageBackend) ([]LogEntry, error) {
	it, err := sb.Scan(ctx, []byte(logPrefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []LogEntry
	for it.Next() {
		var e LogEntry
		if err := json.Unmarshal(it.Value(), &e); err != nil {
			return nil, fmt.Errorf("raft: corrupt log entry: %w", err)
		}
		out = append(out, e)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Package raft implements core Raft consensus (Diego Ongaro & John
// Ousterhout, "In Search of an Understandable Consensus Algorithm"):
// randomized-timeout leader election, log replication via AppendEntries
// with the standard log-matching consistency checks, and commit-index
// advancement requiring acknowledgment from a majority of a FIXED set of
// nodes configured at startup.
//
// Explicit scope boundary — what this does NOT implement:
//   - Cluster membership changes (joint consensus / adding-removing nodes
//     at runtime). The peer set is fixed for the lifetime of a cluster;
//     changing it requires stopping and reconfiguring every node.
//   - Log compaction / snapshotting. The log grows without bound — a
//     long-running deployment needs a follow-up snapshotting mechanism
//     before this is production-viable for sustained high write volume.
//   - Client request forwarding beyond reporting the current leader's
//     node ID via Leader() — a Propose call against a non-leader node
//     simply errors with that information; it does not transparently
//     forward the request itself.
//
// This is a separate, new, opt-in plugin — it does not modify or replace
// plugins/replication (gossip membership + async replication), which
// remains the right choice for anyone who doesn't need strict
// consensus/quorum-write guarantees and wants dynamic membership instead.
package raft

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

type role int

const (
	roleFollower role = iota
	roleCandidate
	roleLeader
)

func (r role) String() string {
	switch r {
	case roleFollower:
		return "follower"
	case roleCandidate:
		return "candidate"
	case roleLeader:
		return "leader"
	default:
		return "unknown"
	}
}

type peerInfo struct {
	id   string
	addr string
}

// RequestVoteReq/Resp and AppendEntriesReq/Resp are the two real Raft RPCs.
type RequestVoteReq struct {
	Term         int64  `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex int64  `json:"last_log_index"`
	LastLogTerm  int64  `json:"last_log_term"`
}

type RequestVoteResp struct {
	Term        int64 `json:"term"`
	VoteGranted bool  `json:"vote_granted"`
}

type AppendEntriesReq struct {
	Term         int64      `json:"term"`
	LeaderID     string     `json:"leader_id"`
	PrevLogIndex int64      `json:"prev_log_index"`
	PrevLogTerm  int64      `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries,omitempty"`
	LeaderCommit int64      `json:"leader_commit"`
}

type AppendEntriesResp struct {
	Term          int64 `json:"term"`
	Success       bool  `json:"success"`
	ConflictIndex int64 `json:"conflict_index,omitempty"`
	ConflictTerm  int64 `json:"conflict_term,omitempty"`
}

// noopFSM is used until SetFSM is called (see plugin.go) so Propose still
// exercises the real consensus path (election/replication/commit) even
// before an application wires up its own state machine.
type noopFSM struct{}

func (noopFSM) Apply([]byte) error { return nil }

// Raft is one node's consensus state machine.
type Raft struct {
	mu sync.Mutex

	id    string
	peers []peerInfo // excludes self

	sb     api.StorageBackend
	fsm    api.RaftFSM
	logger api.Logger

	currentTerm int64
	votedFor    string
	log         []LogEntry // 1-based: log[i] has Index == i+1 (no compaction, always contiguous from 1)

	commitIndex int64
	lastApplied int64

	role             role
	leaderID         string
	electionDeadline time.Time
	leaderStopCh     chan struct{}

	nextIndex  map[string]int64
	matchIndex map[string]int64

	proposeWaiters map[int64][]chan error

	electionTimeoutMin time.Duration
	electionTimeoutMax time.Duration
	heartbeatInterval  time.Duration
	rpcTimeout         time.Duration

	server *rpcServer

	applySignal chan struct{}
	stopCh      chan struct{}
	stopped     bool
	wg          sync.WaitGroup

	rngMu sync.Mutex
	rng   *rand.Rand

	// blocked, when non-nil, is consulted before every outbound RPC to
	// simulate a network partition in tests without changing peer
	// configuration — a peer address for which it returns true is treated
	// exactly like an unreachable/timed-out peer. Always nil (no effect)
	// outside tests; see SetPartitionFilter.
	blockedMu sync.RWMutex
	blocked   func(peerAddr string) bool
}

// SetPartitionFilter installs a test-only hook that makes outbound RPCs to
// any peer address for which blocked returns true fail immediately, as if
// that peer were unreachable — used to simulate a real network partition
// in tests. Passing nil (the default) restores normal behavior. This has
// no effect on the wire protocol or any persisted state; it only gates
// whether this node attempts to dial a given peer.
func (r *Raft) SetPartitionFilter(blocked func(peerAddr string) bool) {
	r.blockedMu.Lock()
	r.blocked = blocked
	r.blockedMu.Unlock()
}

func (r *Raft) isBlocked(addr string) bool {
	r.blockedMu.RLock()
	defer r.blockedMu.RUnlock()
	return r.blocked != nil && r.blocked(addr)
}

// Config bundles NewRaft's tunables.
type Config struct {
	ID                 string
	BindAddr           string
	Peers              []peerInfo
	Storage            api.StorageBackend
	FSM                api.RaftFSM
	Logger             api.Logger
	ElectionTimeoutMin time.Duration
	ElectionTimeoutMax time.Duration
	HeartbeatInterval  time.Duration
	RPCTimeout         time.Duration
}

// NewRaft constructs and starts one Raft node: loads any persisted
// term/vote/log from cfg.Storage, opens its RPC listener, and begins the
// election-timeout/heartbeat background loops.
func NewRaft(cfg Config) (*Raft, error) {
	if cfg.FSM == nil {
		cfg.FSM = noopFSM{}
	}
	if cfg.ElectionTimeoutMin == 0 {
		cfg.ElectionTimeoutMin = 150 * time.Millisecond
	}
	if cfg.ElectionTimeoutMax == 0 {
		cfg.ElectionTimeoutMax = 300 * time.Millisecond
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 50 * time.Millisecond
	}
	if cfg.RPCTimeout == 0 {
		cfg.RPCTimeout = 500 * time.Millisecond
	}

	ctx := context.Background()
	term, err := loadTerm(ctx, cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("raft: load term: %w", err)
	}
	votedFor, err := loadVotedFor(ctx, cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("raft: load votedFor: %w", err)
	}
	log, err := loadLog(ctx, cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("raft: load log: %w", err)
	}

	r := &Raft{
		id:                 cfg.ID,
		peers:              cfg.Peers,
		sb:                 cfg.Storage,
		fsm:                cfg.FSM,
		logger:             cfg.Logger,
		currentTerm:        term,
		votedFor:           votedFor,
		log:                log,
		role:               roleFollower,
		nextIndex:          make(map[string]int64),
		matchIndex:         make(map[string]int64),
		proposeWaiters:     make(map[int64][]chan error),
		electionTimeoutMin: cfg.ElectionTimeoutMin,
		electionTimeoutMax: cfg.ElectionTimeoutMax,
		heartbeatInterval:  cfg.HeartbeatInterval,
		rpcTimeout:         cfg.RPCTimeout,
		applySignal:        make(chan struct{}, 1),
		stopCh:             make(chan struct{}),
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	r.resetElectionDeadlineLocked()

	server, err := newRPCServer(cfg.BindAddr, r.rpcHandle)
	if err != nil {
		return nil, err
	}
	r.server = server

	r.wg.Add(2)
	go r.run()
	go r.applyLoop()

	return r, nil
}

// Addr returns the real bound RPC listener address.
func (r *Raft) Addr() string { return r.server.Addr() }

// Stop halts background loops and closes the RPC listener.
func (r *Raft) Stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	r.stopLeaderLoopLocked()
	r.mu.Unlock()

	close(r.stopCh)
	r.server.Stop()
	r.wg.Wait()
}

var _ api.RaftService = (*Raft)(nil)

// ---- api.RaftService ----

func (r *Raft) IsLeader() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.role == roleLeader
}

func (r *Raft) Leader() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.leaderID == "" {
		return "", false
	}
	return r.leaderID, true
}

func (r *Raft) Propose(ctx context.Context, data []byte) error {
	r.mu.Lock()
	if r.role != roleLeader {
		leader := r.leaderID
		r.mu.Unlock()
		if leader != "" {
			return fmt.Errorf("raft: not leader, current leader is %q", leader)
		}
		return fmt.Errorf("raft: not leader, no known leader")
	}
	lastIdx, _ := r.lastLogInfoLocked()
	idx := lastIdx + 1
	term := r.currentTerm
	entry := LogEntry{Term: term, Index: idx, Data: data}
	r.log = append(r.log, entry)
	waitCh := make(chan error, 1)
	r.proposeWaiters[idx] = append(r.proposeWaiters[idx], waitCh)
	peers := append([]peerInfo{}, r.peers...)
	r.mu.Unlock()

	if err := persistLogEntry(context.Background(), r.sb, entry); err != nil {
		return err
	}

	if len(peers) == 0 {
		r.mu.Lock()
		if r.commitIndex < idx {
			r.commitIndex = idx
		}
		r.mu.Unlock()
		r.signalApply()
	} else {
		for _, p := range peers {
			go r.replicateToPeer(p, term)
		}
	}

	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---- background loops ----

func (r *Raft) run() {
	defer r.wg.Done()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.tick()
		}
	}
}

func (r *Raft) tick() {
	r.mu.Lock()
	if r.role == roleLeader {
		r.mu.Unlock()
		return
	}
	expired := time.Now().After(r.electionDeadline)
	r.mu.Unlock()
	if expired {
		r.startElection()
	}
}

func (r *Raft) applyLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.stopCh:
			return
		case <-r.applySignal:
			r.applyPending()
		}
	}
}

func (r *Raft) signalApply() {
	select {
	case r.applySignal <- struct{}{}:
	default:
	}
}

func (r *Raft) applyPending() {
	for {
		r.mu.Lock()
		if r.lastApplied >= r.commitIndex {
			r.mu.Unlock()
			return
		}
		idx := r.lastApplied + 1
		entry, ok := r.entryAtLocked(idx)
		if !ok {
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()

		var applyErr error
		if r.fsm != nil {
			applyErr = r.fsm.Apply(entry.Data)
		}

		r.mu.Lock()
		r.lastApplied = idx
		waiters := r.proposeWaiters[idx]
		delete(r.proposeWaiters, idx)
		r.mu.Unlock()

		for _, ch := range waiters {
			ch <- applyErr
		}
	}
}

// ---- elections ----

func (r *Raft) startElection() {
	r.mu.Lock()
	r.currentTerm++
	term := r.currentTerm
	r.votedFor = r.id
	r.role = roleCandidate
	r.leaderID = ""
	r.resetElectionDeadlineLocked()
	lastIdx, lastTerm := r.lastLogInfoLocked()
	peers := append([]peerInfo{}, r.peers...)
	_ = persistTerm(context.Background(), r.sb, term)
	_ = persistVotedFor(context.Background(), r.sb, r.id)
	majority := (len(r.peers)+1)/2 + 1
	r.mu.Unlock()

	if len(peers) == 0 {
		r.mu.Lock()
		if r.role == roleCandidate && r.currentTerm == term {
			r.becomeLeaderLocked()
		}
		r.mu.Unlock()
		return
	}

	granted := 1 // voted for self

	for _, p := range peers {
		p := p
		go func() {
			if r.isBlocked(p.addr) {
				return
			}
			req := RequestVoteReq{Term: term, CandidateID: r.id, LastLogIndex: lastIdx, LastLogTerm: lastTerm}
			var resp RequestVoteResp
			if err := rpcCall(p.addr, kindRequestVote, req, &resp, r.rpcTimeout); err != nil {
				return
			}

			r.mu.Lock()
			defer r.mu.Unlock()
			if resp.Term > r.currentTerm {
				r.stepDownLocked(resp.Term)
				return
			}
			if r.role != roleCandidate || r.currentTerm != term || !resp.VoteGranted {
				return
			}
			granted++
			if granted >= majority && r.role == roleCandidate && r.currentTerm == term {
				r.becomeLeaderLocked()
			}
		}()
	}
}

func (r *Raft) becomeLeaderLocked() {
	r.role = roleLeader
	r.leaderID = r.id
	lastIdx, _ := r.lastLogInfoLocked()
	r.nextIndex = make(map[string]int64, len(r.peers))
	r.matchIndex = make(map[string]int64, len(r.peers))
	for _, p := range r.peers {
		r.nextIndex[p.id] = lastIdx + 1
		r.matchIndex[p.id] = 0
	}
	r.leaderStopCh = make(chan struct{})
	stopCh := r.leaderStopCh
	term := r.currentTerm
	r.wg.Add(1)
	go r.leaderLoop(term, stopCh)
}

func (r *Raft) stepDownLocked(term int64) {
	r.currentTerm = term
	r.votedFor = ""
	r.role = roleFollower
	r.leaderID = ""
	_ = persistTerm(context.Background(), r.sb, term)
	_ = persistVotedFor(context.Background(), r.sb, "")
	r.resetElectionDeadlineLocked()
	r.stopLeaderLoopLocked()
}

func (r *Raft) stopLeaderLoopLocked() {
	if r.leaderStopCh != nil {
		close(r.leaderStopCh)
		r.leaderStopCh = nil
	}
}

func (r *Raft) resetElectionDeadlineLocked() {
	span := r.electionTimeoutMax - r.electionTimeoutMin
	jitter := time.Duration(0)
	if span > 0 {
		r.rngMu.Lock()
		jitter = time.Duration(r.rng.Int63n(int64(span)))
		r.rngMu.Unlock()
	}
	r.electionDeadline = time.Now().Add(r.electionTimeoutMin + jitter)
}

// ---- replication (leader side) ----

func (r *Raft) leaderLoop(term int64, stopCh chan struct{}) {
	defer r.wg.Done()
	r.replicateAll(term)
	ticker := time.NewTicker(r.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.mu.Lock()
			stillLeader := r.role == roleLeader && r.currentTerm == term
			r.mu.Unlock()
			if !stillLeader {
				return
			}
			r.replicateAll(term)
		}
	}
}

func (r *Raft) replicateAll(term int64) {
	r.mu.Lock()
	peers := append([]peerInfo{}, r.peers...)
	r.mu.Unlock()
	for _, p := range peers {
		go r.replicateToPeer(p, term)
	}
}

func (r *Raft) replicateToPeer(p peerInfo, term int64) {
	if r.isBlocked(p.addr) {
		return
	}
	r.mu.Lock()
	if r.role != roleLeader || r.currentTerm != term {
		r.mu.Unlock()
		return
	}
	ni := r.nextIndex[p.id]
	if ni < 1 {
		ni = 1
	}
	prevLogIndex := ni - 1
	prevLogTerm := r.termAtLocked(prevLogIndex)
	entries := r.entriesFromLocked(ni)
	req := AppendEntriesReq{
		Term: term, LeaderID: r.id,
		PrevLogIndex: prevLogIndex, PrevLogTerm: prevLogTerm,
		Entries: entries, LeaderCommit: r.commitIndex,
	}
	r.mu.Unlock()

	var resp AppendEntriesResp
	if err := rpcCall(p.addr, kindAppendEntries, req, &resp, r.rpcTimeout); err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if resp.Term > r.currentTerm {
		r.stepDownLocked(resp.Term)
		return
	}
	if r.role != roleLeader || r.currentTerm != term {
		return
	}
	if resp.Success {
		newMatch := prevLogIndex + int64(len(entries))
		if newMatch > r.matchIndex[p.id] {
			r.matchIndex[p.id] = newMatch
		}
		if newMatch+1 > r.nextIndex[p.id] {
			r.nextIndex[p.id] = newMatch + 1
		}
		r.advanceCommitIndexLocked(term)
		return
	}

	switch {
	case resp.ConflictTerm != 0:
		if idx := r.lastIndexOfTermLocked(resp.ConflictTerm); idx > 0 {
			r.nextIndex[p.id] = idx + 1
		} else {
			r.nextIndex[p.id] = resp.ConflictIndex
		}
	case resp.ConflictIndex > 0:
		r.nextIndex[p.id] = resp.ConflictIndex
	default:
		if r.nextIndex[p.id] > 1 {
			r.nextIndex[p.id]--
		}
	}
}

func (r *Raft) advanceCommitIndexLocked(term int64) {
	lastIdx, _ := r.lastLogInfoLocked()
	majority := (len(r.peers)+1)/2 + 1
	for n := lastIdx; n > r.commitIndex; n-- {
		if r.termAtLocked(n) != term {
			continue // Raft safety: only commit current-term entries directly
		}
		count := 1 // self
		for _, p := range r.peers {
			if r.matchIndex[p.id] >= n {
				count++
			}
		}
		if count >= majority {
			r.commitIndex = n
			r.signalApply()
			return
		}
	}
}

// ---- RPC handlers (follower/candidate side) ----

func (r *Raft) rpcHandle(kind byte, body []byte) (any, error) {
	switch kind {
	case kindRequestVote:
		var req RequestVoteReq
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		return r.handleRequestVote(req), nil
	case kindAppendEntries:
		var req AppendEntriesReq
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		return r.handleAppendEntries(req), nil
	default:
		return nil, fmt.Errorf("raft: unknown rpc kind %d", kind)
	}
}

func (r *Raft) handleRequestVote(req RequestVoteReq) RequestVoteResp {
	r.mu.Lock()
	defer r.mu.Unlock()

	if req.Term > r.currentTerm {
		r.stepDownLocked(req.Term)
	}
	if req.Term < r.currentTerm {
		return RequestVoteResp{Term: r.currentTerm, VoteGranted: false}
	}

	lastIdx, lastTerm := r.lastLogInfoLocked()
	logOK := req.LastLogTerm > lastTerm || (req.LastLogTerm == lastTerm && req.LastLogIndex >= lastIdx)

	if (r.votedFor == "" || r.votedFor == req.CandidateID) && logOK {
		r.votedFor = req.CandidateID
		_ = persistVotedFor(context.Background(), r.sb, req.CandidateID)
		r.resetElectionDeadlineLocked()
		return RequestVoteResp{Term: r.currentTerm, VoteGranted: true}
	}
	return RequestVoteResp{Term: r.currentTerm, VoteGranted: false}
}

func (r *Raft) handleAppendEntries(req AppendEntriesReq) AppendEntriesResp {
	r.mu.Lock()
	defer r.mu.Unlock()

	if req.Term > r.currentTerm {
		r.stepDownLocked(req.Term)
	}
	if req.Term < r.currentTerm {
		return AppendEntriesResp{Term: r.currentTerm, Success: false}
	}

	r.role = roleFollower
	r.leaderID = req.LeaderID
	r.resetElectionDeadlineLocked()

	lastIdx, _ := r.lastLogInfoLocked()

	if req.PrevLogIndex > 0 {
		if req.PrevLogIndex > lastIdx {
			return AppendEntriesResp{Term: r.currentTerm, Success: false, ConflictIndex: lastIdx + 1}
		}
		if r.termAtLocked(req.PrevLogIndex) != req.PrevLogTerm {
			conflictTerm := r.termAtLocked(req.PrevLogIndex)
			conflictIndex := req.PrevLogIndex
			for conflictIndex > 1 && r.termAtLocked(conflictIndex-1) == conflictTerm {
				conflictIndex--
			}
			return AppendEntriesResp{Term: r.currentTerm, Success: false, ConflictIndex: conflictIndex, ConflictTerm: conflictTerm}
		}
	}

	insertAt := req.PrevLogIndex + 1
	for i, e := range req.Entries {
		idx := insertAt + int64(i)
		if idx <= lastIdx {
			if r.termAtLocked(idx) == e.Term {
				continue
			}
			r.log = r.log[:idx-1]
			_ = truncateLogFrom(context.Background(), r.sb, idx, lastIdx)
			lastIdx = idx - 1
		}
		r.log = append(r.log, e)
		_ = persistLogEntry(context.Background(), r.sb, e)
		lastIdx = idx
	}

	if req.LeaderCommit > r.commitIndex {
		newCommit := req.LeaderCommit
		if newCommit > lastIdx {
			newCommit = lastIdx
		}
		if newCommit > r.commitIndex {
			r.commitIndex = newCommit
			r.signalApply()
		}
	}

	return AppendEntriesResp{Term: r.currentTerm, Success: true}
}

// ---- log helpers (1-based, contiguous — no compaction) ----

func (r *Raft) lastLogInfoLocked() (index int64, term int64) {
	if len(r.log) == 0 {
		return 0, 0
	}
	last := r.log[len(r.log)-1]
	return last.Index, last.Term
}

func (r *Raft) termAtLocked(index int64) int64 {
	if index <= 0 || index > int64(len(r.log)) {
		return 0
	}
	return r.log[index-1].Term
}

func (r *Raft) entryAtLocked(index int64) (LogEntry, bool) {
	if index <= 0 || index > int64(len(r.log)) {
		return LogEntry{}, false
	}
	return r.log[index-1], true
}

func (r *Raft) entriesFromLocked(from int64) []LogEntry {
	if from <= 0 || from > int64(len(r.log)) {
		return nil
	}
	out := make([]LogEntry, len(r.log)-int(from)+1)
	copy(out, r.log[from-1:])
	return out
}

func (r *Raft) lastIndexOfTermLocked(term int64) int64 {
	for i := len(r.log) - 1; i >= 0; i-- {
		if r.log[i].Term == term {
			return r.log[i].Index
		}
		if r.log[i].Term < term {
			break
		}
	}
	return 0
}

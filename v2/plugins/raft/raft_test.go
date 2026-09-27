package raft

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	mem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

// recordingFSM appends every applied entry, in order, guarded by a mutex
// so tests can safely inspect it from the main goroutine while Raft's
// apply loop runs concurrently.
type recordingFSM struct {
	mu      sync.Mutex
	applied [][]byte
}

func (f *recordingFSM) Apply(entry []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(entry))
	copy(cp, entry)
	f.applied = append(f.applied, cp)
	return nil
}

func (f *recordingFSM) snapshot() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.applied))
	copy(out, f.applied)
	return out
}

// testNode bundles one Raft node with its FSM for assertions.
type testNode struct {
	id  string
	r   *Raft
	fsm *recordingFSM
}

// newCluster builds n Raft nodes, all on 127.0.0.1 with OS-assigned
// ports, each node's peer list containing every OTHER node (full mesh,
// fixed membership — matching this implementation's documented scope).
// Each node gets its own in-memory storage backend (independent "disk").
func newCluster(t *testing.T, n int) []*testNode {
	t.Helper()

	// Two-phase construction: first reserve an address for every node by
	// starting its RPC listener via a throwaway Raft, OR simpler — bind
	// listeners up front outside Raft, then hand the real addresses into
	// NewRaft's peer config. Simplest correct approach here: construct
	// nodes one at a time, but a node started before its peers exist
	// still works — the algorithm never assumes peers are reachable in
	// order, only that their EVENTUAL addresses are correct, so we do a
	// two-pass approach: allocate IDs and reserve real addresses first
	// using bare listeners, close them, then hand those addresses to
	// NewRaft. There's a small unavoidable TOCTOU window (port reuse)
	// acceptable for a test on loopback.
	ids := make([]string, n)
	addrs := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("node%d", i)
		ln, err := newRPCServer("127.0.0.1:0", func(byte, []byte) (any, error) { return nil, nil })
		if err != nil {
			t.Fatalf("reserve addr: %v", err)
		}
		addrs[i] = ln.Addr()
		ln.Stop()
	}

	nodes := make([]*testNode, n)
	for i := 0; i < n; i++ {
		var peers []peerInfo
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			peers = append(peers, peerInfo{id: ids[j], addr: addrs[j]})
		}
		fsm := &recordingFSM{}
		r, err := NewRaft(Config{
			ID:                 ids[i],
			BindAddr:           addrs[i],
			Peers:              peers,
			Storage:            mem.NewEngine(),
			FSM:                fsm,
			ElectionTimeoutMin: 100 * time.Millisecond,
			ElectionTimeoutMax: 200 * time.Millisecond,
			HeartbeatInterval:  25 * time.Millisecond,
			RPCTimeout:         500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewRaft(%s): %v", ids[i], err)
		}
		nodes[i] = &testNode{id: ids[i], r: r, fsm: fsm}
	}

	t.Cleanup(func() {
		for _, n := range nodes {
			n.r.Stop()
		}
	})
	return nodes
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func findLeader(nodes []*testNode) *testNode {
	for _, n := range nodes {
		if n.r.IsLeader() {
			return n
		}
	}
	return nil
}

// TestBasicThreeNodeCluster (scenario 1): elect a leader, Propose several
// entries, confirm all 3 nodes' FSMs apply them in the same order.
func TestBasicThreeNodeCluster(t *testing.T) {
	nodes := newCluster(t, 3)

	var leader *testNode
	if !waitFor(t, 3*time.Second, func() bool {
		leader = findLeader(nodes)
		return leader != nil
	}) {
		t.Fatal("no leader elected within timeout")
	}

	entries := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for _, e := range entries {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := leader.r.Propose(ctx, e)
		cancel()
		if err != nil {
			t.Fatalf("Propose(%s): %v", e, err)
		}
	}

	for _, n := range nodes {
		ok := waitFor(t, 2*time.Second, func() bool { return len(n.fsm.snapshot()) == len(entries) })
		if !ok {
			t.Fatalf("node %s: expected %d applied entries, got %d", n.id, len(entries), len(n.fsm.snapshot()))
		}
		got := n.fsm.snapshot()
		for i, e := range entries {
			if string(got[i]) != string(e) {
				t.Fatalf("node %s: entry %d = %q, want %q", n.id, i, got[i], e)
			}
		}
	}
}

// TestLeaderFailureAndReElection (scenario 2): kill the leader, confirm
// the remaining nodes elect a new leader and old entries are preserved,
// and new Proposes against the new leader still work.
func TestLeaderFailureAndReElection(t *testing.T) {
	nodes := newCluster(t, 3)

	var leader *testNode
	if !waitFor(t, 3*time.Second, func() bool {
		leader = findLeader(nodes)
		return leader != nil
	}) {
		t.Fatal("no initial leader elected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := leader.r.Propose(ctx, []byte("before-failure")); err != nil {
		cancel()
		t.Fatalf("initial Propose: %v", err)
	}
	cancel()

	oldLeaderID := leader.id
	leader.r.Stop()

	var survivors []*testNode
	for _, n := range nodes {
		if n.id != oldLeaderID {
			survivors = append(survivors, n)
		}
	}

	var newLeader *testNode
	if !waitFor(t, 5*time.Second, func() bool {
		newLeader = findLeader(survivors)
		return newLeader != nil && newLeader.id != oldLeaderID
	}) {
		t.Fatal("no new leader elected after old leader's failure")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	err := newLeader.r.Propose(ctx2, []byte("after-failure"))
	cancel2()
	if err != nil {
		t.Fatalf("Propose against new leader: %v", err)
	}

	for _, n := range survivors {
		ok := waitFor(t, 2*time.Second, func() bool { return len(n.fsm.snapshot()) == 2 })
		if !ok {
			t.Fatalf("survivor %s: expected 2 applied entries, got %d", n.id, len(n.fsm.snapshot()))
		}
		got := n.fsm.snapshot()
		if string(got[0]) != "before-failure" || string(got[1]) != "after-failure" {
			t.Fatalf("survivor %s: applied = %q, %q; want before-failure, after-failure", n.id, got[0], got[1])
		}
	}
}

// TestNetworkPartitionMajorityMinority (scenario 3): partition a 5-node
// cluster into a majority (3) and minority (2) via SetPartitionFilter.
// The majority side must still be able to elect a leader and commit; the
// minority side must NOT be able to commit anything. Healing the
// partition must let the minority catch up without diverging.
func TestNetworkPartitionMajorityMinority(t *testing.T) {
	nodes := newCluster(t, 5)

	if !waitFor(t, 3*time.Second, func() bool { return findLeader(nodes) != nil }) {
		t.Fatal("no initial leader elected")
	}

	majority := nodes[:3]
	minority := nodes[3:]

	addrOf := func(n *testNode) string { return n.r.Addr() }
	majorityAddrs := map[string]bool{}
	for _, n := range majority {
		majorityAddrs[addrOf(n)] = true
	}
	minorityAddrs := map[string]bool{}
	for _, n := range minority {
		minorityAddrs[addrOf(n)] = true
	}

	for _, n := range majority {
		n.r.SetPartitionFilter(func(addr string) bool { return minorityAddrs[addr] })
	}
	for _, n := range minority {
		n.r.SetPartitionFilter(func(addr string) bool { return majorityAddrs[addr] })
	}

	// Force a fresh election within the majority partition: whichever
	// side the current leader is on, the OTHER side (if it was the
	// minority) needed to lose its leader; if the leader happened to be
	// in the majority already, it keeps leading. Either way, wait for the
	// majority side specifically to have a leader post-partition.
	var majLeader *testNode
	if !waitFor(t, 5*time.Second, func() bool {
		majLeader = findLeader(majority)
		return majLeader != nil
	}) {
		t.Fatal("majority side never elected/kept a leader after partition")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := majLeader.r.Propose(ctx, []byte("majority-write")); err != nil {
		cancel()
		t.Fatalf("majority Propose: %v", err)
	}
	cancel()

	for _, n := range majority {
		if !waitFor(t, 2*time.Second, func() bool { return len(n.fsm.snapshot()) == 1 }) {
			t.Fatalf("majority node %s did not apply the committed entry", n.id)
		}
	}

	// Minority side: it must never be able to commit. Give it a real
	// chance to try (it may elect its OWN "leader" among just its 2
	// nodes, since Raft has no way to know 5 is the intended total once
	// isolated — the actual safety property is about COMMITTING entries,
	// which requires a majority of the FULL configured peer set, not just
	// of whoever happens to be reachable). Assert no minority node ever
	// applies anything.
	time.Sleep(1 * time.Second)
	for _, n := range minority {
		if got := len(n.fsm.snapshot()); got != 0 {
			t.Fatalf("minority node %s applied %d entries during partition — must be 0", n.id, got)
		}
	}

	// Heal the partition.
	for _, n := range nodes {
		n.r.SetPartitionFilter(nil)
	}

	for _, n := range minority {
		if !waitFor(t, 5*time.Second, func() bool { return len(n.fsm.snapshot()) == 1 }) {
			t.Fatalf("minority node %s did not catch up after healing", n.id)
		}
		if string(n.fsm.snapshot()[0]) != "majority-write" {
			t.Fatalf("minority node %s diverged: applied %q, want majority-write", n.id, n.fsm.snapshot()[0])
		}
	}
}

// TestPersistedStateSurvivesRestart (scenario 4, simplified per the
// honest scope note in this package's test report: this simulates a
// crash-restart by Stop()ping a node and constructing a brand new *Raft
// against the SAME StorageBackend instance — proving the persisted
// term/vote/log survive and are correctly reloaded — rather than a real
// OS-level SIGKILL subprocess as productiontest/ uses elsewhere. The
// durability guarantee under test is about the StorageBackend read/write
// path, which is identical either way; a real subprocess-kill variant
// would additionally exercise process-level signal handling, which this
// plugin has none of (it has no independent process lifecycle beyond the
// Go process embedding it), so the simpler in-process simulation exercises
// the same real code path a true process restart would.
func TestPersistedStateSurvivesRestart(t *testing.T) {
	storage := mem.NewEngine() // shared "disk" across the simulated restart

	ln, err := newRPCServer("127.0.0.1:0", func(byte, []byte) (any, error) { return nil, nil })
	if err != nil {
		t.Fatalf("reserve addr: %v", err)
	}
	addr := ln.Addr()
	ln.Stop()

	fsm1 := &recordingFSM{}
	r1, err := NewRaft(Config{
		ID: "solo", BindAddr: addr, Storage: storage, FSM: fsm1,
		ElectionTimeoutMin: 60 * time.Millisecond, ElectionTimeoutMax: 100 * time.Millisecond, HeartbeatInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRaft: %v", err)
	}

	if !waitFor(t, 2*time.Second, func() bool { return r1.IsLeader() }) {
		t.Fatal("solo node never became leader")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := r1.Propose(ctx, []byte("persisted-entry")); err != nil {
		cancel()
		t.Fatalf("Propose: %v", err)
	}
	cancel()

	termBefore, err := loadTerm(context.Background(), storage)
	if err != nil {
		t.Fatalf("loadTerm: %v", err)
	}
	vf, err := loadVotedFor(context.Background(), storage)
	if err != nil {
		t.Fatalf("loadVotedFor: %v", err)
	}

	r1.Stop() // simulated crash

	fsm2 := &recordingFSM{}
	r2, err := NewRaft(Config{
		ID: "solo", BindAddr: addr, Storage: storage, FSM: fsm2,
		ElectionTimeoutMin: 60 * time.Millisecond, ElectionTimeoutMax: 100 * time.Millisecond, HeartbeatInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRaft (restart): %v", err)
	}
	defer r2.Stop()

	r2.mu.Lock()
	termAfter := r2.currentTerm
	voteAfter := r2.votedFor
	logLenAfter := len(r2.log)
	r2.mu.Unlock()

	if termAfter != termBefore {
		t.Fatalf("term not preserved across restart: before=%d after=%d", termBefore, termAfter)
	}
	if voteAfter != vf {
		t.Fatalf("votedFor not preserved across restart: before=%q after=%q", vf, voteAfter)
	}
	if logLenAfter != 1 {
		t.Fatalf("log not preserved across restart: got %d entries, want 1", logLenAfter)
	}

	// Re-elects itself as sole leader (no peers). commitIndex itself is
	// NOT persisted (only term/vote/log are, per standard Raft) — and per
	// the Raft safety rule, a new leader cannot mark PRE-EXISTING entries
	// from a prior term as committed just by re-becoming leader; it only
	// does so once it commits a NEW entry in its own current term (Raft
	// paper §5.4.2 / Figure 8). So Propose-ing one new entry here is
	// expected to cause BOTH the reloaded old entry and the new entry to
	// apply, back to back — assert on the final settled state (which
	// entry, in which order) rather than an intermediate count, since the
	// two applies happen too close together for a poll to reliably catch
	// the transient len==1 state in between.
	if !waitFor(t, 2*time.Second, func() bool { return r2.IsLeader() }) {
		t.Fatal("restarted solo node never became leader")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	if err := r2.Propose(ctx2, []byte("post-restart-entry")); err != nil {
		cancel2()
		t.Fatalf("Propose after restart: %v", err)
	}
	cancel2()
	if !waitFor(t, 2*time.Second, func() bool { return len(fsm2.snapshot()) == 2 }) {
		t.Fatalf("expected both the reloaded and new entry applied, got %d: %q", len(fsm2.snapshot()), fsm2.snapshot())
	}
	final := fsm2.snapshot()
	if string(final[0]) != "persisted-entry" || string(final[1]) != "post-restart-entry" {
		t.Fatalf("applied order wrong: got %q, %q", final[0], final[1])
	}
}

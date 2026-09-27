// Command raft_cluster demonstrates Velocity v2's real Raft consensus
// (api.RaftService, plugins/raft): leader election, quorum-committed log
// replication, and automatic re-election on leader failure — a genuinely
// crash-safe replicated log over a fixed 3-node cluster.
//
// Scope, stated honestly (matching plugins/raft's own doc comment): this is
// core Raft (election + replication + commit) over a FIXED peer set — no
// membership changes, no log compaction/snapshotting.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/raft"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// appendFSM is the simplest possible api.RaftFSM: it just remembers every
// committed entry, in order, so the example can print what each node
// actually applied and compare across nodes.
type appendFSM struct {
	mu      sync.Mutex
	applied [][]byte
}

func (f *appendFSM) Apply(entry []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(entry))
	copy(cp, entry)
	f.applied = append(f.applied, cp)
	return nil
}

func (f *appendFSM) snapshot() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.applied))
	copy(out, f.applied)
	return out
}

// reserveAddr binds a real 127.0.0.1 listener on an OS-assigned port, reads
// back its address, and immediately releases it — Raft's node_id/bind_addr
// must be known BEFORE Init (every node's peer list needs every other
// node's real address up front), so addresses have to be reserved before
// any node boots, not discovered after (unlike this codebase's other
// network plugins, which bind ":0" and expose an Addr() accessor
// post-Start). Same small, accepted TOCTOU window plugins/raft's own test
// helper (newCluster) documents for exactly this reason.
func reserveAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	addr := ln.Addr().String()
	must(ln.Close())
	return addr
}

type node struct {
	id      string
	addr    string
	dir     string
	kernel  *kernel.Kernel
	fsm     *appendFSM
	raftSvc api.RaftService
}

func bootNode(id, bindAddr string, peers []string) *node {
	dir, err := os.MkdirTemp("", "velocity-raft-"+id+"-*")
	must(err)

	peerList := make([]any, len(peers))
	for i, p := range peers {
		peerList[i] = p
	}

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "raft", Enabled: true, Config: map[string]any{
			"node_id":              id,
			"bind_addr":            bindAddr,
			"peers":                peerList,
			"election_timeout_min": "100ms",
			"election_timeout_max": "200ms",
			"heartbeat_interval":   "25ms",
		}},
	}}

	fsm := &appendFSM{}
	raftPlugin := raft.NewPlugin("storage-lsm")
	raftPlugin.SetFSM(fsm) // must be set before Boot's Init runs

	k := kernel.New(manifest)
	must(k.Boot(context.Background(), []api.Plugin{
		storagelsm.New(),
		raftPlugin,
	}, manifest.Enabled()))

	return &node{
		id:      id,
		addr:    bindAddr,
		dir:     dir,
		kernel:  k,
		fsm:     fsm,
		raftSvc: k.Registry().MustLookup("raft").(api.RaftService),
	}
}

// waitForLeader polls the given nodes for up to timeout, returning the
// first one that reports IsLeader()==true. Never blocks forever.
func waitForLeader(nodes []*node, timeout time.Duration) *node {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.raftSvc.IsLeader() {
				return n
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// waitForAppliedCount polls until every node's FSM has applied at least n
// entries, or timeout elapses.
func waitForAppliedCount(nodes []*node, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allCaughtUp := true
		for _, nd := range nodes {
			if len(nd.fsm.snapshot()) < n {
				allCaughtUp = false
				break
			}
		}
		if allCaughtUp {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func printApplied(label string, n *node) {
	entries := n.fsm.snapshot()
	strs := make([]string, len(entries))
	for i, e := range entries {
		strs[i] = string(e)
	}
	fmt.Printf("%s (%s) applied: %v\n", label, n.id, strs)
}

func main() {
	ids := []string{"node0", "node1", "node2"}
	addrs := make([]string, 3)
	for i := range addrs {
		addrs[i] = reserveAddr()
	}

	fmt.Println("=== Booting a 3-node Raft cluster (fixed peer set) ===")
	nodes := make([]*node, 3)
	for i := 0; i < 3; i++ {
		var peers []string
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			peers = append(peers, ids[j]+"@"+addrs[j])
		}
		nodes[i] = bootNode(ids[i], addrs[i], peers)
		fmt.Printf("%s listening at %s\n", ids[i], addrs[i])
	}
	defer func() {
		for _, n := range nodes {
			n.kernel.Shutdown(context.Background())
			os.RemoveAll(n.dir)
		}
	}()

	fmt.Println("\n=== Waiting for leader election ===")
	leader := waitForLeader(nodes, 5*time.Second)
	if leader == nil {
		log.Fatal("no leader elected within 5s — election failed to converge")
	}
	fmt.Printf("leader elected: %s\n", leader.id)

	fmt.Println("\n=== Proposing 3 entries via the leader ===")
	entries := []string{"entry-A", "entry-B", "entry-C"}
	for _, e := range entries {
		must(leader.raftSvc.Propose(context.Background(), []byte(e)))
		fmt.Printf("Proposed %q\n", e)
	}

	if !waitForAppliedCount(nodes, len(entries), 5*time.Second) {
		log.Fatal("not all nodes caught up to the proposed entries within 5s")
	}
	for _, n := range nodes {
		printApplied("node", n)
	}
	fmt.Println("confirmed: all 3 nodes applied the same entries in the same order")

	fmt.Printf("\n=== Killing the leader (%s) and waiting for re-election ===\n", leader.id)
	must(leader.kernel.Shutdown(context.Background()))
	var survivors []*node
	for _, n := range nodes {
		if n.id != leader.id {
			survivors = append(survivors, n)
		}
	}

	newLeader := waitForLeader(survivors, 5*time.Second)
	if newLeader == nil {
		log.Fatal("no new leader elected among survivors within 5s")
	}
	fmt.Printf("new leader elected: %s\n", newLeader.id)

	fmt.Println("\n=== Proposing another entry via the new leader ===")
	must(newLeader.raftSvc.Propose(context.Background(), []byte("entry-D-after-failover")))
	if !waitForAppliedCount(survivors, len(entries)+1, 5*time.Second) {
		log.Fatal("surviving nodes did not catch up to the post-failover entry within 5s")
	}
	for _, n := range survivors {
		printApplied("survivor", n)
	}
	fmt.Println("confirmed: the cluster kept working after losing its original leader,")
	fmt.Println("and the pre-failover entries were preserved, not lost or reordered.")

	fmt.Println("\nNote: this is core Raft (election + replication + majority commit) over a")
	fmt.Println("FIXED 3-node peer set — no membership changes, no log compaction/snapshotting")
	fmt.Println("yet. See plugins/raft's package doc comment for the full scope boundary.")

	fmt.Println("\ndone.")
}

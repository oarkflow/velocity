// Command replication_cluster demonstrates Velocity v2's replication
// plugin: gossip-style membership (join/leave), consistent-hash key
// routing, and the honest scope limit stated in api.ClusterMembership's
// own doc comment — this is NOT a consensus/quorum system, just
// membership tracking and routing.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/replication"
)

func main() {
	ctx := context.Background()

	// --- Node A: the seed node ---
	manifestA := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "replication", Enabled: true, Config: map[string]any{
				"node_id":   "node-a",
				"bind_addr": "127.0.0.1:0", // OS-assigned port, never conflicts
			}},
		},
	}
	kA := kernel.New(manifestA)
	pluginA := replication.NewPlugin("node-a", "127.0.0.1:0", "")
	must(kA.Boot(ctx, []api.Plugin{pluginA}, manifestA.Enabled()))
	defer kA.Shutdown(ctx)

	membershipA := kA.Registry().MustLookup("cluster").(api.ClusterMembership)
	nodeAAddr := selfAddress(membershipA, "node-a")
	fmt.Printf("=== Node A started, listening on %s ===\n", nodeAAddr)

	// --- Node B: joins via node A as its seed ---
	manifestB := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "replication", Enabled: true, Config: map[string]any{
				"node_id":   "node-b",
				"bind_addr": "127.0.0.1:0",
				"seed":      nodeAAddr,
			}},
		},
	}
	kB := kernel.New(manifestB)
	pluginB := replication.NewPlugin("node-b", "127.0.0.1:0", nodeAAddr)
	must(kB.Boot(ctx, []api.Plugin{pluginB}, manifestB.Enabled()))
	defer kB.Shutdown(ctx)

	membershipB := kB.Registry().MustLookup("cluster").(api.ClusterMembership)
	fmt.Println("=== Node B started and joined via node A's seed address ===")

	fmt.Println("\n=== Membership: both nodes should see each other ===")
	membersA, err := waitForMemberCount(membershipA, 2, 5*time.Second)
	must(err)
	printMembers("node A's view", membersA)

	membersB, err := waitForMemberCount(membershipB, 2, 5*time.Second)
	must(err)
	printMembers("node B's view", membersB)

	fmt.Println("\n=== Consistent-hash routing: NodeForKey is stable across repeated calls ===")
	key := []byte("customer-42")
	owner := membershipA.NodeForKey(key)
	fmt.Printf("key %q routes to node %s\n", key, owner.ID)
	for i := 0; i < 3; i++ {
		again := membershipA.NodeForKey(key)
		if again.ID != owner.ID {
			log.Fatalf("routing is not stable: got %s, then %s", owner.ID, again.ID)
		}
	}
	fmt.Println("confirmed stable across 3 repeated calls")

	fmt.Println("\n=== Node B leaves gracefully ===")
	must(membershipB.Leave(ctx))
	remaining, err := waitForMemberCount(membershipA, 1, 5*time.Second)
	must(err)
	printMembers("node A's view after node B left", remaining)

	fmt.Println("\ndone. (Note: this is gossip-style membership + async replication," +
		" NOT a consensus protocol — no leader election, no quorum writes," +
		" same honest scope as v1. See api.ClusterMembership's doc comment.)")
}

// selfAddress polls Members() until it finds selfID, returning its
// real bound address (only known after Start binds a ":0" listener).
func selfAddress(m api.ClusterMembership, selfID string) string {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range m.Members() {
			if n.ID == selfID && n.Address != "" {
				return n.Address
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Fatalf("timed out waiting for %s's bound address", selfID)
	return ""
}

// waitForMemberCount polls Members() with a bounded retry loop rather
// than a blind sleep, since gossip convergence is asynchronous.
func waitForMemberCount(m api.ClusterMembership, want int, timeout time.Duration) ([]api.NodeInfo, error) {
	deadline := time.Now().Add(timeout)
	var last []api.NodeInfo
	for time.Now().Before(deadline) {
		last = m.Members()
		if len(last) == want {
			return last, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last, fmt.Errorf("timed out waiting for %d member(s), last saw %d", want, len(last))
}

func printMembers(label string, members []api.NodeInfo) {
	fmt.Printf("%s:\n", label)
	for _, m := range members {
		fmt.Printf("  - %s at %s (state=%s)\n", m.ID, m.Address, m.State)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

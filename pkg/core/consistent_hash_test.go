package core

import (
	"fmt"
	"sort"
	"testing"
)

func TestConsistentHashRing(t *testing.T) {
	t.Run("AddNode adds to ring and NodeCount returns correct count", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-1")
		ring.AddNode("node-2")
		ring.AddNode("node-3")

		if got := ring.NodeCount(); got != 3 {
			t.Fatalf("expected 3 nodes, got %d", got)
		}
	})

	t.Run("RemoveNode removes from ring", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-1")
		ring.AddNode("node-2")
		ring.RemoveNode("node-1")

		if ring.HasNode("node-1") {
			t.Fatal("node-1 should have been removed")
		}
		if got := ring.NodeCount(); got != 1 {
			t.Fatalf("expected 1 node after removal, got %d", got)
		}
	})

	t.Run("GetNode returns consistent results for same key", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-a")
		ring.AddNode("node-b")
		ring.AddNode("node-c")

		key := "my-important-key"
		first := ring.GetNode(key)
		for i := 0; i < 100; i++ {
			got := ring.GetNode(key)
			if got != first {
				t.Fatalf("inconsistent result on iteration %d: got %q, want %q", i, got, first)
			}
		}
	})

	t.Run("GetNode distributes across nodes", func(t *testing.T) {
		ring := NewConsistentHashRing(256)
		ring.AddNode("node-x")
		ring.AddNode("node-y")
		ring.AddNode("node-z")

		counts := map[string]int{}
		numKeys := 10000
		for i := 0; i < numKeys; i++ {
			node := ring.GetNode(fmt.Sprintf("key-%d", i))
			counts[node]++
		}

		minExpected := numKeys / 10
		for node, count := range counts {
			if count < minExpected {
				t.Errorf("node %s got only %d keys (minimum expected %d)", node, count, minExpected)
			}
		}
		if len(counts) != 3 {
			t.Fatalf("expected keys on 3 nodes, got %d", len(counts))
		}
	})

	t.Run("GetNodes returns N distinct nodes for replication", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("r1")
		ring.AddNode("r2")
		ring.AddNode("r3")
		ring.AddNode("r4")

		nodes := ring.GetNodes("repl-key", 3)
		if len(nodes) != 3 {
			t.Fatalf("expected 3 nodes, got %d", len(nodes))
		}

		seen := map[string]bool{}
		for _, n := range nodes {
			if seen[n] {
				t.Fatalf("duplicate node %q in GetNodes result", n)
			}
			seen[n] = true
		}
	})

	t.Run("GetNodes caps at available node count", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("only-1")
		ring.AddNode("only-2")

		nodes := ring.GetNodes("some-key", 10)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes (capped), got %d", len(nodes))
		}
	})

	t.Run("GetRebalanceMap returns source nodes affected by new node", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("existing-1")
		ring.AddNode("existing-2")

		rebalanceMap := ring.GetRebalanceMap("new-node")
		if len(rebalanceMap) == 0 {
			t.Fatal("expected non-empty rebalance map")
		}
		for src := range rebalanceMap {
			if src != "existing-1" && src != "existing-2" {
				t.Errorf("unexpected source node %q in rebalance map", src)
			}
		}
	})

	t.Run("HasNode and ListNodes", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("alpha")
		ring.AddNode("beta")

		if !ring.HasNode("alpha") {
			t.Fatal("expected HasNode(alpha) == true")
		}
		if ring.HasNode("gamma") {
			t.Fatal("expected HasNode(gamma) == false")
		}

		nodes := ring.ListNodes()
		sort.Strings(nodes)
		if len(nodes) != 2 || nodes[0] != "alpha" || nodes[1] != "beta" {
			t.Fatalf("expected [alpha beta], got %v", nodes)
		}
	})

	t.Run("Empty ring returns empty string and nil", func(t *testing.T) {
		ring := NewConsistentHashRing(64)

		if got := ring.GetNode("any-key"); got != "" {
			t.Fatalf("expected empty string from empty ring, got %q", got)
		}
		if got := ring.GetNodes("any-key", 3); got != nil {
			t.Fatalf("expected nil from empty ring GetNodes, got %v", got)
		}
	})
}

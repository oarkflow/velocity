package replication

import "testing"

func TestHashRing_ConsistentOwnershipAcrossTopologyChange(t *testing.T) {
	r := newHashRing(100)
	nodes := []string{"n1", "n2", "n3", "n4"}
	for _, n := range nodes {
		r.AddNode(n)
	}

	keys := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		keys = append(keys, string(rune('a'+i%26))+string(rune(i)))
	}

	before := make(map[string]string, len(keys))
	for _, k := range keys {
		before[k] = r.GetNode(k)
	}

	// Standard consistent-hashing property: adding one node should only
	// remap keys that land on that node's ring positions — most keys
	// should keep their owner.
	r.AddNode("n5")

	moved := 0
	for _, k := range keys {
		if r.GetNode(k) != before[k] {
			moved++
		}
	}
	fraction := float64(moved) / float64(len(keys))
	if fraction > 0.5 {
		t.Fatalf("too many keys remapped after adding one node: %.2f%% moved (expected roughly 1/5 with 5 nodes)", fraction*100)
	}
	t.Logf("%.2f%% of keys remapped after adding a 5th node", fraction*100)

	if r.NodeCount() != 5 {
		t.Fatalf("expected 5 nodes, got %d", r.NodeCount())
	}

	r.RemoveNode("n5")
	if r.NodeCount() != 4 {
		t.Fatalf("expected 4 nodes after removal, got %d", r.NodeCount())
	}
	for _, k := range keys {
		if got := r.GetNode(k); got != before[k] {
			t.Fatalf("key %q owner changed after remove-then-restore: got %q want %q", k, got, before[k])
		}
	}
}

func TestHashRing_EmptyRingReturnsNoOwner(t *testing.T) {
	r := newHashRing(0)
	if got := r.GetNode("anything"); got != "" {
		t.Fatalf("expected empty owner on empty ring, got %q", got)
	}
}

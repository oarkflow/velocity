package search

import (
	"context"
	"sort"
	"testing"
)

func TestGraphStoreTraversal(t *testing.T) {
	ctx := context.Background()
	kv := newMemKV()
	g := newGraphStore(kv)

	// A -> B -> C -> D
	// A -> E
	entities := []string{"A", "B", "C", "D", "E"}
	for _, e := range entities {
		if err := g.AddEntity(ctx, e, map[string]any{"name": e}); err != nil {
			t.Fatalf("AddEntity(%s): %v", e, err)
		}
	}
	edges := [][2]string{{"A", "B"}, {"B", "C"}, {"C", "D"}, {"A", "E"}}
	for _, e := range edges {
		if err := g.AddRelation(ctx, e[0], e[1], "links_to", nil); err != nil {
			t.Fatalf("AddRelation(%s->%s): %v", e[0], e[1], err)
		}
	}

	cases := []struct {
		depth int
		want  []string
	}{
		{0, []string{"A"}},
		{1, []string{"A", "B", "E"}},
		{2, []string{"A", "B", "C", "E"}},
		{3, []string{"A", "B", "C", "D", "E"}},
	}

	for _, c := range cases {
		got, err := g.Traverse(ctx, "A", c.depth)
		if err != nil {
			t.Fatalf("Traverse(depth=%d): %v", c.depth, err)
		}
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("Traverse(depth=%d) = %v, want %v", c.depth, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("Traverse(depth=%d) = %v, want %v", c.depth, got, want)
			}
		}
	}
}

package search

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// bruteForceTopK computes the exact k nearest neighbors by cosine
// similarity via linear scan, used only to cross-check HNSW's
// approximate results in this test — never as a production path.
func bruteForceTopK(vectors map[string][]float32, query []float32, k int) []string {
	type scored struct {
		id   string
		dist float64
	}
	scoredList := make([]scored, 0, len(vectors))
	for id, v := range vectors {
		scoredList = append(scoredList, scored{id: id, dist: cosineSimilarity(query, v)})
	}
	sort.Slice(scoredList, func(i, j int) bool { return scoredList[i].dist > scoredList[j].dist })
	if len(scoredList) > k {
		scoredList = scoredList[:k]
	}
	out := make([]string, len(scoredList))
	for i, s := range scoredList {
		out[i] = s.id
	}
	return out
}

func randomVector(rng *rand.Rand, dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rng.Float32()*2 - 1
	}
	return v
}

func TestVectorIndexHNSWRecall(t *testing.T) {
	ctx := context.Background()
	const (
		dim = 12
		n   = 500
		k   = 10
	)

	kv := newMemKV()
	idx := newVectorIndex(kv, hnswConfig{Dimension: dim, M: 16, EfConstruction: 200, EfSearch: 64})

	rng := rand.New(rand.NewSource(42))
	vectors := make(map[string][]float32, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("v%d", i)
		vec := randomVector(rng, dim)
		vectors[id] = vec
		if err := idx.Upsert(ctx, id, vec, nil); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}

	query := randomVector(rng, dim)
	hnswResults, err := idx.Search(ctx, query, k)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hnswResults) == 0 {
		t.Fatalf("Search returned no results")
	}

	exact := bruteForceTopK(vectors, query, k)
	exactSet := make(map[string]bool, len(exact))
	for _, id := range exact {
		exactSet[id] = true
	}

	overlap := 0
	for _, h := range hnswResults {
		if exactSet[h.Key] {
			overlap++
		}
	}
	recall := float64(overlap) / float64(len(exact))
	if recall < 0.8 {
		t.Fatalf("HNSW recall = %.2f (overlap %d/%d with brute-force top-%d), want >= 0.80", recall, overlap, len(exact), k)
	}
	t.Logf("HNSW recall vs brute-force top-%d: %.2f (%d/%d)", k, recall, overlap, len(exact))
}

func TestVectorIndexUpsertReplacesAndDeleteRepairs(t *testing.T) {
	ctx := context.Background()
	const dim = 4
	kv := newMemKV()
	idx := newVectorIndex(kv, hnswConfig{Dimension: dim, M: 4, EfConstruction: 32, EfSearch: 16})

	vecs := map[string][]float32{
		"a": {1, 0, 0, 0},
		"b": {0, 1, 0, 0},
		"c": {0, 0, 1, 0},
	}
	for id, v := range vecs {
		if err := idx.Upsert(ctx, id, v, map[string]any{"label": id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	if idx.nodeCount != 3 {
		t.Fatalf("nodeCount = %d, want 3", idx.nodeCount)
	}

	// Upsert an existing id with a new vector: must not grow node count,
	// and the new vector must take effect.
	if err := idx.Upsert(ctx, "a", []float32{0, 0, 0, 1}, nil); err != nil {
		t.Fatalf("Upsert replace: %v", err)
	}
	if idx.nodeCount != 3 {
		t.Fatalf("nodeCount after replace = %d, want 3", idx.nodeCount)
	}
	hits, err := idx.Search(ctx, []float32{0, 0, 0, 1}, 1)
	if err != nil {
		t.Fatalf("Search after replace: %v", err)
	}
	if len(hits) != 1 || hits[0].Key != "a" {
		t.Fatalf("Search after replacing 'a' = %+v, want top hit 'a'", hits)
	}

	// Delete must remove the node and repair remaining neighbor lists
	// (no dangling references to a deleted node).
	if err := idx.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete(b): %v", err)
	}
	if idx.nodeCount != 2 {
		t.Fatalf("nodeCount after delete = %d, want 2", idx.nodeCount)
	}
	for id, node := range idx.nodes {
		for layer, friends := range node.friends {
			for _, f := range friends {
				if f == "b" {
					t.Fatalf("node %s layer %d still references deleted node 'b'", id, layer)
				}
			}
		}
	}
}

// Command search_and_kg shows Velocity v2's search plugin end to end:
// full-text indexing (term/phrase/negative-term queries), HNSW vector
// similarity search (nearest neighbors over two obviously-clustered
// groups), a small knowledge graph with BFS traversal, and the
// entity-extraction/resolution/chunking text-mining surface.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	searchplugin "github.com/oarkflow/velocity/v2/plugins/search"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-search-demo-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
		// vector_dimension is small (8) here purely so the nearest-neighbor
		// example below is easy to eyeball; production use would match
		// whatever embedding model's real dimensionality (e.g. 384/1536).
		{Name: "search", Enabled: true, Config: map[string]any{"vector_dimension": 8}},
	}}

	k := kernel.New(manifest)
	ctx := context.Background()
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), searchplugin.NewPlugin("kv")}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	fulltextDemo(ctx, k)
	vectorDemo(ctx, k)
	graphDemo(ctx, k)
	entitiesDemo(ctx, k)

	fmt.Println("\ndone.")
}

func fulltextDemo(ctx context.Context, k *kernel.Kernel) {
	section("1. Full-text search")
	idx := lookup[api.SearchIndex](k, searchplugin.ServiceFullText)

	docs := map[string]map[string]any{
		"doc1": {"title": "The quick brown fox", "body": "jumps over the lazy dog"},
		"doc2": {"title": "The quick blue hare", "body": "jumps over the sleepy cat"},
		"doc3": {"title": "A slow green turtle", "body": "walks past the lazy dog"},
	}
	for key, fields := range docs {
		must(idx.Index(ctx, key, fields))
	}
	fmt.Println("indexed doc1, doc2, doc3")

	hits, err := idx.Query(ctx, "quick", 10)
	must(err)
	fmt.Printf(`Query("quick")            -> %s`+"\n", keys(hits))

	hits, err = idx.Query(ctx, "jumps -cat", 10)
	must(err)
	fmt.Printf(`Query("jumps -cat")       -> %s (doc2 excluded: contains "cat")`+"\n", keys(hits))

	hits, err = idx.Query(ctx, `"lazy dog"`, 10)
	must(err)
	fmt.Printf(`Query("\"lazy dog\"")       -> %s (phrase match)`+"\n", keys(hits))
}

func vectorDemo(ctx context.Context, k *kernel.Kernel) {
	section("2. HNSW vector search")
	idx := lookup[api.VectorIndex](k, searchplugin.ServiceVector)

	// Two obviously separated clusters in 8-dim space: "fruit" vectors
	// near [1,1,1,1,0,0,0,0], "vehicle" vectors near [0,0,0,0,1,1,1,1].
	fruits := map[string][]float32{
		"apple":  {1.0, 0.9, 1.1, 1.0, 0.0, 0.1, 0.0, 0.0},
		"banana": {0.9, 1.0, 1.0, 0.9, 0.1, 0.0, 0.0, 0.1},
		"cherry": {1.1, 1.0, 0.9, 1.1, 0.0, 0.0, 0.1, 0.0},
	}
	vehicles := map[string][]float32{
		"car":  {0.0, 0.1, 0.0, 0.0, 1.0, 0.9, 1.1, 1.0},
		"bike": {0.1, 0.0, 0.1, 0.0, 0.9, 1.0, 1.0, 0.9},
	}
	for id, v := range fruits {
		must(idx.Upsert(ctx, id, v, map[string]any{"category": "fruit"}))
	}
	for id, v := range vehicles {
		must(idx.Upsert(ctx, id, v, map[string]any{"category": "vehicle"}))
	}
	fmt.Println("upserted 3 fruit vectors + 2 vehicle vectors")

	query := []float32{1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0} // clearly "fruit"-like
	hits, err := idx.Search(ctx, query, 3)
	must(err)
	fmt.Print("Search(fruit-like query, k=3) ->")
	for _, h := range hits {
		fmt.Printf(" %s(%.3f)", h.Key, h.Score)
	}
	fmt.Println(" (expect all 3 to be fruits, not vehicles)")
}

func graphDemo(ctx context.Context, k *kernel.Kernel) {
	section("3. Knowledge graph traversal")
	g := lookup[api.GraphStore](k, searchplugin.ServiceGraph)

	// A -> B -> C -> D
	// A -> E
	for _, e := range []string{"A", "B", "C", "D", "E"} {
		must(g.AddEntity(ctx, e, map[string]any{"name": e}))
	}
	for _, edge := range [][2]string{{"A", "B"}, {"B", "C"}, {"C", "D"}, {"A", "E"}} {
		must(g.AddRelation(ctx, edge[0], edge[1], "links_to", nil))
	}
	fmt.Println("built graph: A->B->C->D, A->E")

	for _, depth := range []int{1, 2} {
		reached, err := g.Traverse(ctx, "A", depth)
		must(err)
		sort.Strings(reached)
		fmt.Printf("Traverse(A, depth=%d) -> %v\n", depth, reached)
	}
}

func entitiesDemo(ctx context.Context, k *kernel.Kernel) {
	section("4. Entity extraction, resolution, chunking")
	svc := lookup[api.EntityExtractionService](k, searchplugin.ServiceEntities)

	text := "Contact Dr. John Smith at john.smith@example.com or visit https://example.com. " +
		"Acme Technologies Inc. signed on 2024-03-15 for $12,500.00."
	entities, err := svc.ExtractEntities(ctx, text)
	must(err)
	fmt.Println("extracted entities:")
	for _, e := range entities {
		fmt.Printf("  [%s] %q\n", e.Type, e.Text)
	}

	res, err := svc.ResolveEntities(ctx, []string{"acme corp", "acme corp.", "widget inc"})
	must(err)
	fmt.Println("resolved clusters (near-duplicates merged):")
	for _, r := range res {
		fmt.Printf("  canonical=%q merged=%v\n", r.CanonicalID, r.MergedIDs)
	}

	long := strings.Repeat("word ", 300)
	chunks, err := svc.ChunkText(ctx, long, 100)
	must(err)
	fmt.Printf("ChunkText(300 words, maxWords=100) -> %d chunks\n", len(chunks))
}

func lookup[T any](k *kernel.Kernel, name string) T {
	svc, ok := k.Registry().Lookup(name)
	if !ok {
		log.Fatalf("service %q not registered", name)
	}
	v, ok := svc.(T)
	if !ok {
		log.Fatalf("service %q is not the expected type", name)
	}
	return v
}

func keys(hits []api.SearchHit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.Key
	}
	sort.Strings(out)
	return out
}

func section(title string) { fmt.Printf("\n=== %s ===\n", title) }

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

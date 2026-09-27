package search

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// graphStore is a simplified knowledge-graph store, covering the
// AddEntity/AddRelation/Traverse surface of api.GraphStore. It is a
// deliberately smaller port than v1's pkg/kg graph store: v1's
// KGGraphStore also has ontology validation, a mutation log, shortest
// path, and connected-components — all out of scope for this pass, which
// prioritizes correctness of the HNSW vector index (the algorithmically
// hardest piece) over graph feature completeness. A future pass can layer
// those features on top of this same key scheme without changing it.
//
// Key scheme:
//
//	search/graph/entity/<id>              -> JSON attrs
//	search/graph/rel/<from>/<relType>/<to> -> JSON attrs (directed edge)
type graphStore struct {
	kv api.KVService
}

func newGraphStore(kv api.KVService) *graphStore {
	return &graphStore{kv: kv}
}

const (
	graphEntityPfx = "search/graph/entity/"
	graphRelPfx    = "search/graph/rel/"
)

func (g *graphStore) AddEntity(ctx context.Context, id string, attrs map[string]any) error {
	if id == "" {
		return fmt.Errorf("search: entity id must not be empty")
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("search: encode entity %q attrs: %w", id, err)
	}
	return g.kv.Put(ctx, graphEntityPfx+id, data)
}

func (g *graphStore) AddRelation(ctx context.Context, from, to, relType string, attrs map[string]any) error {
	if from == "" || to == "" || relType == "" {
		return fmt.Errorf("search: relation requires non-empty from, to, and relType")
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("search: encode relation %s-%s->%s attrs: %w", from, relType, to, err)
	}
	return g.kv.Put(ctx, graphRelPfx+from+"/"+relType+"/"+to, data)
}

// Traverse performs a real BFS from start, up to depth hops along
// directed (from -> to) edges, returning every entity ID reached
// (including start itself).
func (g *graphStore) Traverse(ctx context.Context, start string, depth int) ([]string, error) {
	if start == "" {
		return nil, fmt.Errorf("search: traverse start must not be empty")
	}
	if depth < 0 {
		depth = 0
	}

	type queued struct {
		id        string
		remaining int
	}

	visited := map[string]bool{start: true}
	order := []string{start}
	queue := []queued{{id: start, remaining: depth}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.remaining <= 0 {
			continue
		}
		neighbors, err := g.outgoing(ctx, cur.id)
		if err != nil {
			return nil, err
		}
		for _, to := range neighbors {
			if visited[to] {
				continue
			}
			visited[to] = true
			order = append(order, to)
			queue = append(queue, queued{id: to, remaining: cur.remaining - 1})
		}
	}

	return order, nil
}

func (g *graphStore) outgoing(ctx context.Context, from string) ([]string, error) {
	prefix := graphRelPfx + from + "/"
	var out []string
	cursor := ""
	for {
		items, next, err := g.kv.Scan(ctx, prefix, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for fullKey := range items {
			rest := strings.TrimPrefix(fullKey, prefix)
			// rest is "<relType>/<to>" — relType never contains '/', so
			// splitting on the first '/' recovers <to> even if it did.
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) == 2 {
				out = append(out, parts[1])
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

var _ api.GraphStore = (*graphStore)(nil)

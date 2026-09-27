// Package search implements Velocity v2's search plugin: full-text
// indexing (ported from v1's search_index.go query-parsing approach),
// vector similarity search via a real multi-layer HNSW graph (ported from
// v1's pkg/kg/hnsw.go), and a knowledge-graph entity/relation store with
// BFS/DFS traversal (a simplified port of v1's pkg/kg graph store,
// covering AddEntity/AddRelation/Traverse — the full ontology-validation
// and shortest-path machinery from v1 is out of scope for this pass).
//
// All three surfaces persist through an api.KVService looked up from the
// registry, not a StorageBackend directly, so this plugin works atop any
// KV implementation.
package search

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// Service names this plugin registers under. Fixed by convention so other
// plugins (and cmd/velocityd) can look them up.
const (
	ServiceFullText = "search.fulltext"
	ServiceVector   = "search.vector"
	ServiceGraph    = "search.graph"
	ServiceEntities = "search.entities"
)

// Plugin wires all three search surfaces (SearchIndex, VectorIndex,
// GraphStore) against a single KVService dependency.
type Plugin struct {
	kvDep string

	kv api.KVService

	fulltext *fullTextIndex
	vector   *vectorIndex
	graph    *graphStore
	entities *entityExtraction

	health api.Health
}

// NewPlugin constructs the search plugin. kvDep names the KV plugin this
// one depends on for boot ordering (Registry lookups always use the fixed
// service name "kv" regardless of which concrete plugin provided it);
// pass "" to use the default, "kv".
func NewPlugin(kvDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	return &Plugin{kvDep: kvDep, health: api.Health{Status: "down", Detail: "not started"}}
}

func (p *Plugin) Name() string    { return "search" }
func (p *Plugin) Version() string { return "0.1.0" }

func (p *Plugin) Dependencies() []string { return []string{p.kvDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	svc := k.Registry().MustLookup("kv")
	kv, ok := svc.(api.KVService)
	if !ok {
		return fmt.Errorf("search: service %q does not implement api.KVService", "kv")
	}
	p.kv = kv

	dim := k.Config().Scoped("search").Int("vector_dimension", 128)
	m := k.Config().Scoped("search").Int("hnsw_m", 16)
	efConstruction := k.Config().Scoped("search").Int("hnsw_ef_construction", 200)
	efSearch := k.Config().Scoped("search").Int("hnsw_ef_search", 50)

	p.fulltext = newFullTextIndex(kv)
	p.vector = newVectorIndex(kv, hnswConfig{
		Dimension:      dim,
		M:              m,
		EfConstruction: efConstruction,
		EfSearch:       efSearch,
	})
	p.graph = newGraphStore(kv)

	resolveThreshold := k.Config().Scoped("search").Raw()["entity_resolve_threshold"]
	threshold := defaultResolveThreshold
	if f, ok := resolveThreshold.(float64); ok {
		threshold = f
	}
	p.entities = newEntityExtraction(threshold)

	if err := k.Registry().Provide(ServiceFullText, api.SearchIndex(p.fulltext)); err != nil {
		return err
	}
	if err := k.Registry().Provide(ServiceVector, api.VectorIndex(p.vector)); err != nil {
		return err
	}
	if err := k.Registry().Provide(ServiceGraph, api.GraphStore(p.graph)); err != nil {
		return err
	}
	if err := k.Registry().Provide(ServiceEntities, api.EntityExtractionService(p.entities)); err != nil {
		return err
	}

	if err := p.vector.loadMeta(ctx); err != nil {
		return fmt.Errorf("search: load vector index metadata: %w", err)
	}

	p.health = api.Health{Status: "ok"}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }

func (p *Plugin) Stop(ctx context.Context) error {
	p.health = api.Health{Status: "down", Detail: "stopped"}
	return nil
}

func (p *Plugin) Health() api.Health { return p.health }

var _ api.Plugin = (*Plugin)(nil)

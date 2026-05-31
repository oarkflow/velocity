package kg

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// KGConfig configures the Knowledge Graph Engine.
type KGConfig struct {
	// Embedding configuration (optional — omit for BM25-only mode)
	EmbeddingEndpoint string // HTTP endpoint for embedding API
	EmbeddingModel    string // model name to send in requests
	EmbeddingDim      int    // vector dimensionality

	// Chunking
	ChunkMaxWords int // words per chunk (default 256)
	ChunkOverlap  int // overlap in words (default 64)

	// Ingest
	IngestWorkers         int // concurrent workers for batch ingest (default 4)
	CustomNERRules        []KGCustomNERRule
	DisableNER            bool          // skip named entity extraction during ingest
	DisableEntityIndexing bool          // skip mirroring extracted mentions into the entity graph during ingest
	DisableDBTextIndex    bool          // skip generic DB text indexing for KG chunks; KG search still indexes chunks itself
	AuthzFilter           KGAuthzFilter // optional per-result authorization hook

	// HNSW tuning
	HNSWM              int // max connections per layer (default 16)
	HNSWEfConstruction int // beam width during build (default 200)
	HNSWEfSearch       int // beam width during search (default 50)
}

// KnowledgeGraphEngine is the top-level orchestrator for the KG subsystem.
type KnowledgeGraphEngine struct {
	db       Store
	pipeline *KGIngestPipeline
	search   *KGSearchEngine
	graph    *KGGraphStore
	hnsw     *HNSWIndex
	embedder KGEmbedder
	ner      *RuleBasedNER
	em       EntityStore
	config   KGConfig
	jobMu    sync.Mutex
	jobStops map[string]context.CancelFunc
}

// NewKnowledgeGraphEngine creates a new KG engine wired to the given DB.
func NewKnowledgeGraphEngine(db Store, config KGConfig, entities ...EntityStore) (*KnowledgeGraphEngine, error) {
	if db == nil {
		return nil, fmt.Errorf("db is required")
	}
	em := EntityStore(noopEntityStore{})
	if len(entities) > 0 && entities[0] != nil {
		em = entities[0]
	}

	engine := &KnowledgeGraphEngine{
		db:       db,
		ner:      NewRuleBasedNER(),
		em:       em,
		graph:    NewKGGraphStore(db),
		config:   config,
		jobStops: make(map[string]context.CancelFunc),
	}
	for _, rule := range config.CustomNERRules {
		if strings.TrimSpace(rule.Type) == "" || strings.TrimSpace(rule.Pattern) == "" {
			continue
		}
		confidence := rule.Confidence
		if confidence <= 0 {
			confidence = 0.75
		}
		if err := engine.ner.AddRule(rule.Type, rule.Pattern, confidence); err != nil {
			return nil, fmt.Errorf("add custom NER rule %s: %w", rule.Type, err)
		}
	}

	// Set up embedder and HNSW if endpoint is configured
	if config.EmbeddingEndpoint != "" && config.EmbeddingDim > 0 {
		engine.embedder = NewHTTPEmbedder(config.EmbeddingEndpoint, config.EmbeddingModel, config.EmbeddingDim)

		hnswConfig := HNSWConfig{
			M:              config.HNSWM,
			EfConstruction: config.HNSWEfConstruction,
			EfSearch:       config.HNSWEfSearch,
			Dimension:      config.EmbeddingDim,
		}
		hnsw, err := NewHNSWIndex(db, hnswConfig)
		if err != nil {
			return nil, fmt.Errorf("init HNSW index: %w", err)
		}
		engine.hnsw = hnsw
	}

	// Set up chunker
	chunker := NewSlidingWindowChunker(config.ChunkMaxWords, config.ChunkOverlap)

	// Set up ingest pipeline
	pipelineEntityStore := engine.em
	if config.DisableEntityIndexing {
		pipelineEntityStore = noopEntityStore{}
	}
	opts := []IngestOption{
		WithChunker(chunker),
		WithEntityStore(pipelineEntityStore),
		WithIngestConfig(IngestConfig{
			Workers:            config.IngestWorkers,
			SkipDuplicate:      true,
			DisableDBTextIndex: config.DisableDBTextIndex,
		}),
	}
	if config.DisableNER {
		opts = append(opts, WithNER(nil))
	} else {
		opts = append(opts, WithNER(engine.ner))
	}
	if engine.embedder != nil {
		opts = append(opts, WithEmbedder(engine.embedder))
	}
	if engine.hnsw != nil {
		opts = append(opts, WithHNSW(engine.hnsw))
	}
	engine.pipeline = NewKGIngestPipeline(db, opts...)

	// Set up search engine
	engine.search = NewKGSearchEngine(db, engine.hnsw, engine.embedder, engine.em)

	// Register BM25 schema for KG chunks
	db.RegisterChunkSearchPrefix(kgChunkSearchPrefix)

	return engine, nil
}

// AddNERRule registers a custom regex entity extractor on the rule-based engine.
func (e *KnowledgeGraphEngine) AddNERRule(rule KGCustomNERRule) error {
	if e == nil || e.ner == nil {
		return fmt.Errorf("knowledge graph NER unavailable")
	}
	if strings.TrimSpace(rule.Type) == "" {
		return fmt.Errorf("rule type is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("rule pattern is required")
	}
	if rule.Confidence <= 0 {
		rule.Confidence = 0.75
	}
	return e.ner.AddRule(rule.Type, rule.Pattern, rule.Confidence)
}

// ListNERRules returns configured rule-based entity extractors.
func (e *KnowledgeGraphEngine) ListNERRules() []KGCustomNERRule {
	if e == nil || e.ner == nil {
		return nil
	}
	return e.ner.ListRules()
}

// Ingest processes a single document.
func (e *KnowledgeGraphEngine) Ingest(ctx context.Context, req *KGIngestRequest) (*KGIngestResponse, error) {
	resp, err := e.pipeline.Ingest(ctx, req)
	if err == nil && e.search != nil && resp != nil {
		_ = e.search.indexDocument(resp.DocID)
	}
	return resp, err
}

// IngestBatch processes multiple documents concurrently.
func (e *KnowledgeGraphEngine) IngestBatch(ctx context.Context, reqs []*KGIngestRequest) ([]*KGIngestResponse, []error) {
	resps, errs := e.pipeline.IngestBatch(ctx, reqs)
	if e.search != nil {
		if e.search.deferredIndexing() {
			e.search.markIndexDirty()
			return resps, errs
		}
		indexed := false
		for i, err := range errs {
			if err == nil && i < len(resps) && resps[i] != nil {
				_ = e.search.indexDocument(resps[i].DocID)
				indexed = true
			}
		}
		if !indexed {
			e.search.markIndexDirty()
		}
	}
	return resps, errs
}

// ImportConnector lists connector items, fetches each item, and ingests the
// fetched content through the normal KG pipeline.
func (e *KnowledgeGraphEngine) ImportConnector(ctx context.Context, connector KGConnector, cursor string, limit int) (*KGConnectorImportResponse, error) {
	if e == nil {
		return nil, fmt.Errorf("knowledge graph engine is nil")
	}
	if connector == nil {
		return nil, fmt.Errorf("connector is required")
	}
	items, nextCursor, err := connector.List(ctx, cursor)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	resp := &KGConnectorImportResponse{
		Connector:  connector.Name(),
		NextCursor: nextCursor,
		Results:    make([]*KGIngestResponse, 0, len(items)),
	}
	for _, item := range items {
		if ctx.Err() != nil {
			resp.Errors = append(resp.Errors, ctx.Err().Error())
			break
		}
		req, err := connector.Fetch(ctx, item)
		if err != nil {
			resp.Skipped++
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		if req == nil {
			resp.Skipped++
			resp.Errors = append(resp.Errors, "connector returned nil ingest request")
			continue
		}
		ingested, err := e.Ingest(ctx, req)
		if err != nil {
			resp.Skipped++
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		resp.Imported++
		resp.Results = append(resp.Results, ingested)
	}
	return resp, nil
}

// Search executes a hybrid search query.
func (e *KnowledgeGraphEngine) Search(ctx context.Context, req *KGSearchRequest) (*KGSearchResponse, error) {
	resp, err := e.search.Search(ctx, req)
	if err != nil || resp == nil {
		return resp, err
	}
	limit := 10
	if req != nil && req.Limit > 0 {
		limit = req.Limit
	}
	if req != nil && req.EnableGraph {
		if err := e.applyGraphSearchScoring(ctx, req, resp, limit); err != nil {
			return nil, err
		}
	}
	if e.config.AuthzFilter == nil {
		return resp, nil
	}
	filtered := resp.Hits[:0]
	for _, hit := range resp.Hits {
		if e.authorized(ctx, KGAuthzResource{
			Kind:     "search_hit",
			ID:       hit.ChunkID,
			Source:   hit.Source,
			Metadata: hit.Metadata,
		}) {
			filtered = append(filtered, hit)
		}
	}
	resp.Hits = filtered
	resp.TotalHits = len(filtered)
	return resp, nil
}

// BeginBulkIndexing defers in-memory text-index maintenance during high-volume
// ingest. Call EndBulkIndexing after the bulk load to build the index once.
func (e *KnowledgeGraphEngine) BeginBulkIndexing() {
	if e != nil && e.search != nil {
		e.search.setDeferredIndexing(true)
	}
	if e != nil && e.pipeline != nil {
		_ = e.pipeline.setBulkStats(true)
	}
}

// EndBulkIndexing rebuilds derived KG indexes after BeginBulkIndexing.
func (e *KnowledgeGraphEngine) EndBulkIndexing(ctx context.Context) error {
	if e == nil || e.search == nil {
		return nil
	}
	if e.pipeline != nil {
		if err := e.pipeline.setBulkStats(false); err != nil {
			return err
		}
	}
	e.search.setDeferredIndexing(false)
	return e.RebuildIndexes(ctx)
}

// GetDocument retrieves a document by ID.
func (e *KnowledgeGraphEngine) GetDocument(docID string) (*KGDocument, error) {
	return e.pipeline.GetDocument(docID)
}

// DeleteDocument removes a document and its indexes.
func (e *KnowledgeGraphEngine) DeleteDocument(docID string) error {
	if e.search != nil {
		e.search.invalidateDocument(docID)
	}
	err := e.pipeline.DeleteDocument(docID)
	return err
}

// DeleteSource removes the KG document associated with a stable source string.
func (e *KnowledgeGraphEngine) DeleteSource(source string) error {
	if e == nil || e.pipeline == nil || source == "" {
		return nil
	}
	data, err := e.db.Get([]byte(kgSourcePrefix + source))
	if err != nil {
		return nil
	}
	docID := string(data)
	if e.search != nil {
		e.search.invalidateDocument(docID)
	}
	err = e.pipeline.DeleteDocument(docID)
	return err
}

// GetAnalytics returns corpus statistics.
func (e *KnowledgeGraphEngine) GetAnalytics() *KGAnalytics {
	stats := e.pipeline.GetStats()
	analytics := &KGAnalytics{
		TotalDocuments: stats.Documents,
		TotalChunks:    stats.Chunks,
		TotalEntities:  stats.Entities,
		EntityTypes:    stats.EntityTypes,
	}

	hnswNodes := 0
	if e.hnsw != nil {
		hnswNodes = e.hnsw.NodeCount()
	}
	_ = hnswNodes

	return analytics
}

// GraphNeighbors returns the entity graph for a given entity ID.
func (e *KnowledgeGraphEngine) GraphNeighbors(ctx context.Context, entityID string, depth int, relationTypes ...string) (*EntityResult, error) {
	if depth <= 0 {
		depth = 1
	}
	relationType := ""
	if len(relationTypes) > 0 {
		relationType = relationTypes[0]
	}
	results, err := e.em.GetRelatedEntities(ctx, entityID, relationType, depth)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("entity not found: %s", entityID)
	}
	return results[0], nil
}

// CreateRelation persists an explicit first-class KG relation.
func (e *KnowledgeGraphEngine) CreateRelation(ctx context.Context, req *KGRelationRequest) (*KGRelation, error) {
	if req != nil && !e.authorized(ctx, KGAuthzResource{Kind: "relation", Source: req.Source, Target: req.Target, RelationType: req.RelationType, Metadata: req.Metadata}) {
		return nil, fmt.Errorf("relation create unauthorized")
	}
	return e.graph.CreateRelation(ctx, req)
}

// GetRelation retrieves a persistent KG relation by ID.
func (e *KnowledgeGraphEngine) GetRelation(ctx context.Context, relationID string) (*KGRelation, error) {
	rel, err := e.graph.GetRelation(ctx, relationID)
	if err != nil {
		return nil, err
	}
	if !e.authorizedRelation(ctx, *rel) {
		return nil, fmt.Errorf("relation not found: %s", relationID)
	}
	return rel, nil
}

// UpdateRelation modifies a persistent KG relation.
func (e *KnowledgeGraphEngine) UpdateRelation(ctx context.Context, relationID string, update *KGRelationUpdate) (*KGRelation, error) {
	rel, err := e.GetRelation(ctx, relationID)
	if err != nil {
		return nil, err
	}
	if !e.authorizedRelation(ctx, *rel) {
		return nil, fmt.Errorf("relation update unauthorized")
	}
	return e.graph.UpdateRelation(ctx, relationID, update)
}

// DeleteRelation marks a persistent KG relation as deleted.
func (e *KnowledgeGraphEngine) DeleteRelation(ctx context.Context, relationID string, actor ...string) error {
	rel, err := e.GetRelation(ctx, relationID)
	if err != nil {
		return err
	}
	if !e.authorizedRelation(ctx, *rel) {
		return fmt.Errorf("relation delete unauthorized")
	}
	return e.graph.DeleteRelation(ctx, relationID, actor...)
}

// QueryRelations filters persistent KG relations.
func (e *KnowledgeGraphEngine) QueryRelations(ctx context.Context, query *KGRelationQuery) ([]KGRelation, error) {
	relations, err := e.graph.QueryRelations(ctx, query)
	if err != nil || e.config.AuthzFilter == nil {
		return relations, err
	}
	filtered := relations[:0]
	for _, rel := range relations {
		if e.authorizedRelation(ctx, rel) {
			filtered = append(filtered, rel)
		}
	}
	return filtered, nil
}

// CreateOntology applies an ontology definition used by relation validation.
func (e *KnowledgeGraphEngine) CreateOntology(ctx context.Context, ontology *KGOntology) (*KGOntology, error) {
	return e.graph.CreateOntology(ctx, ontology)
}

// GetOntology returns a named ontology or the permissive default ontology.
func (e *KnowledgeGraphEngine) GetOntology(ctx context.Context, name string) (*KGOntology, error) {
	return e.graph.GetOntology(ctx, name)
}

// ValidateOntology validates ontology syntax without applying it.
func (e *KnowledgeGraphEngine) ValidateOntology(ontology *KGOntology) KGOntologyValidationResult {
	return ValidateOntologyDefinition(ontology)
}

// QueryGraph traverses persistent KG relations.
func (e *KnowledgeGraphEngine) QueryGraph(ctx context.Context, query *KGGraphQuery) (*KGGraphResponse, error) {
	query, err := e.expandGraphSearchSeeds(ctx, query)
	if err != nil {
		return nil, err
	}
	resp, err := e.graph.QueryGraph(ctx, query)
	if err != nil || resp == nil || e.config.AuthzFilter == nil {
		return resp, err
	}
	relations := resp.Relations[:0]
	nodes := map[string]KGGraphNode{}
	for _, rel := range resp.Relations {
		if e.authorizedRelation(ctx, rel) {
			relations = append(relations, rel)
			for _, node := range resp.Nodes {
				if node.ID == rel.Source || node.ID == rel.Target {
					nodes[node.ID] = node
				}
			}
		}
	}
	resp.Relations = relations
	resp.Nodes = resp.Nodes[:0]
	for _, node := range nodes {
		resp.Nodes = append(resp.Nodes, node)
	}
	return resp, nil
}

func (e *KnowledgeGraphEngine) expandGraphSearchSeeds(ctx context.Context, query *KGGraphQuery) (*KGGraphQuery, error) {
	if query == nil || strings.TrimSpace(query.SeedSearch) == "" {
		return query, nil
	}
	limit := query.SeedSearchLimit
	if limit <= 0 {
		limit = 10
	}
	search, err := e.Search(ctx, &KGSearchRequest{Query: query.SeedSearch, Limit: limit})
	if err != nil {
		return nil, err
	}
	seeds := append([]string(nil), query.SeedIDs...)
	seen := map[string]bool{}
	for _, seed := range seeds {
		seen[seed] = true
	}
	for _, hit := range search.Hits {
		seed := firstNonEmpty(hit.Source, hit.DocID)
		if seed == "" || seen[seed] {
			continue
		}
		seen[seed] = true
		seeds = append(seeds, seed)
	}
	copyQuery := *query
	copyQuery.SeedIDs = seeds
	return &copyQuery, nil
}

// ShortestPath finds the shortest relation path between two nodes.
func (e *KnowledgeGraphEngine) ShortestPath(ctx context.Context, source, target string, query *KGGraphQuery) (*KGGraphPath, error) {
	path, err := e.graph.ShortestPath(ctx, source, target, query)
	if err != nil || e.config.AuthzFilter == nil {
		return path, err
	}
	for _, rel := range path.Relations {
		if !e.authorizedRelation(ctx, rel) {
			return nil, fmt.Errorf("no path found from %s to %s", source, target)
		}
	}
	return path, nil
}

// TraverseImpact traverses outward impact/dependency edges from the supplied seeds.
func (e *KnowledgeGraphEngine) TraverseImpact(ctx context.Context, seeds []string, depth int, relationTypes ...string) (*KGGraphResponse, error) {
	return e.graph.QueryGraph(ctx, &KGGraphQuery{
		SeedIDs:       seeds,
		Depth:         depth,
		Direction:     KGRelationDirectionOut,
		RelationTypes: relationTypes,
	})
}

// GraphMetrics summarizes persistent KG relation degree and count statistics.
func (e *KnowledgeGraphEngine) GraphMetrics(ctx context.Context, query *KGRelationQuery) (*KGGraphMetrics, error) {
	relations, err := e.QueryRelations(ctx, query)
	if err != nil {
		return nil, err
	}
	nodes := map[string]struct{}{}
	metrics := &KGGraphMetrics{
		RelationCount:   len(relations),
		DegreeByNode:    map[string]int{},
		OutDegreeByNode: map[string]int{},
		InDegreeByNode:  map[string]int{},
	}
	for _, rel := range relations {
		nodes[rel.Source] = struct{}{}
		nodes[rel.Target] = struct{}{}
		metrics.DegreeByNode[rel.Source]++
		metrics.DegreeByNode[rel.Target]++
		metrics.OutDegreeByNode[rel.Source]++
		metrics.InDegreeByNode[rel.Target]++
	}
	metrics.NodeCount = len(nodes)
	return metrics, nil
}

// ConnectedComponents returns undirected connected components over persistent relations.
func (e *KnowledgeGraphEngine) ConnectedComponents(ctx context.Context, query *KGGraphQuery) ([][]string, error) {
	graph, err := e.QueryGraph(ctx, query)
	if err != nil {
		return nil, err
	}
	adj := map[string][]string{}
	for _, node := range graph.Nodes {
		adj[node.ID] = nil
	}
	for _, rel := range graph.Relations {
		adj[rel.Source] = append(adj[rel.Source], rel.Target)
		adj[rel.Target] = append(adj[rel.Target], rel.Source)
	}
	visited := map[string]bool{}
	components := [][]string{}
	for node := range adj {
		if visited[node] {
			continue
		}
		stack := []string{node}
		visited[node] = true
		component := []string{}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			component = append(component, current)
			for _, next := range adj[current] {
				if !visited[next] {
					visited[next] = true
					stack = append(stack, next)
				}
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	sort.Slice(components, func(i, j int) bool {
		if len(components[i]) == len(components[j]) {
			return strings.Join(components[i], "\x00") < strings.Join(components[j], "\x00")
		}
		return len(components[i]) > len(components[j])
	})
	return components, nil
}

func (e *KnowledgeGraphEngine) authorizedRelation(ctx context.Context, rel KGRelation) bool {
	return e.authorized(ctx, KGAuthzResource{
		Kind:         "relation",
		ID:           rel.RelationID,
		Source:       rel.Source,
		Target:       rel.Target,
		RelationType: rel.RelationType,
		Metadata:     rel.Metadata,
	})
}

func (e *KnowledgeGraphEngine) authorized(ctx context.Context, resource KGAuthzResource) bool {
	if e == nil || e.config.AuthzFilter == nil {
		return true
	}
	return e.config.AuthzFilter(ctx, resource)
}

// ResolveEntity follows alias redirects and returns the canonical entity ID.
func (e *KnowledgeGraphEngine) ResolveEntity(ctx context.Context, entityID string) (string, []KGEntityAliasRecord, error) {
	return e.graph.ResolveEntity(ctx, entityID)
}

// ProposeMerge records a pending entity merge proposal.
func (e *KnowledgeGraphEngine) ProposeMerge(ctx context.Context, req *KGEntityMergeRequest) (*KGMergeProposal, error) {
	return e.graph.ProposeMerge(ctx, req)
}

// ApproveMerge approves a merge proposal and writes alias redirects.
func (e *KnowledgeGraphEngine) ApproveMerge(ctx context.Context, proposalID, reviewedBy string) (*KGMergeProposal, error) {
	return e.graph.ApproveMerge(ctx, proposalID, reviewedBy)
}

// RejectMerge rejects a pending entity merge proposal.
func (e *KnowledgeGraphEngine) RejectMerge(ctx context.Context, proposalID, reviewedBy string) (*KGMergeProposal, error) {
	return e.graph.RejectMerge(ctx, proposalID, reviewedBy)
}

// ListMergeProposals lists merge proposals, optionally filtered by status.
func (e *KnowledgeGraphEngine) ListMergeProposals(ctx context.Context, status KGMergeStatus) ([]KGMergeProposal, error) {
	return e.graph.ListMergeProposals(ctx, status)
}

// MergeEntities immediately redirects source entity IDs to the target entity ID.
func (e *KnowledgeGraphEngine) MergeEntities(ctx context.Context, req *KGEntityMergeRequest) ([]KGEntityAliasRecord, error) {
	return e.graph.MergeEntities(ctx, req)
}

// SplitEntity removes alias redirects for the supplied entity aliases.
func (e *KnowledgeGraphEngine) SplitEntity(ctx context.Context, aliases []string, actor string) error {
	return e.graph.SplitEntity(ctx, aliases, actor)
}

// ListMutationLog returns recent graph mutation records for replay/rebuild hooks.
func (e *KnowledgeGraphEngine) ListMutationLog(ctx context.Context, limit int) ([]KGMutationLogRecord, error) {
	return e.graph.ListMutationLog(ctx, limit)
}

// RebuildIndexes refreshes derived in-process KG indexes for single-node recovery.
func (e *KnowledgeGraphEngine) RebuildIndexes(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.search != nil {
		e.search.markIndexDirty()
		if err := e.search.ensureTextIndex(); err != nil {
			return err
		}
	}
	if err := e.graph.RebuildIndexes(ctx); err != nil {
		return err
	}
	_, err := e.graph.GraphMetrics(ctx, nil)
	return err
}

// HasVectorSearch returns true if vector search is available.
func (e *KnowledgeGraphEngine) HasVectorSearch() bool {
	return e.hnsw != nil && e.embedder != nil
}

// FlushIndex persists all in-memory HNSW adjacency lists to disk.
func (e *KnowledgeGraphEngine) FlushIndex() error {
	if e.hnsw != nil {
		return e.hnsw.FlushAdjacency()
	}
	return nil
}

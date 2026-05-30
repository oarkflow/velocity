package kg

import (
	"context"
	"fmt"
	"strings"
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
	IngestWorkers  int // concurrent workers for batch ingest (default 4)
	CustomNERRules []KGCustomNERRule

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
	hnsw     *HNSWIndex
	embedder KGEmbedder
	ner      *RuleBasedNER
	em       EntityStore
	config   KGConfig
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
		db:     db,
		ner:    NewRuleBasedNER(),
		em:     em,
		config: config,
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
	opts := []IngestOption{
		WithChunker(chunker),
		WithNER(engine.ner),
		WithEntityStore(engine.em),
		WithIngestConfig(IngestConfig{
			Workers:       config.IngestWorkers,
			SkipDuplicate: true,
		}),
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
	if err == nil && e.search != nil {
		e.search.markIndexDirty()
	}
	return resp, err
}

// IngestBatch processes multiple documents concurrently.
func (e *KnowledgeGraphEngine) IngestBatch(ctx context.Context, reqs []*KGIngestRequest) ([]*KGIngestResponse, []error) {
	resps, errs := e.pipeline.IngestBatch(ctx, reqs)
	if e.search != nil {
		for _, err := range errs {
			if err == nil {
				e.search.markIndexDirty()
				break
			}
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
	return e.search.Search(ctx, req)
}

// GetDocument retrieves a document by ID.
func (e *KnowledgeGraphEngine) GetDocument(docID string) (*KGDocument, error) {
	return e.pipeline.GetDocument(docID)
}

// DeleteDocument removes a document and its indexes.
func (e *KnowledgeGraphEngine) DeleteDocument(docID string) error {
	err := e.pipeline.DeleteDocument(docID)
	if err == nil && e.search != nil {
		e.search.invalidateDocument(docID)
	}
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
	err = e.pipeline.DeleteDocument(docID)
	if err == nil && e.search != nil {
		e.search.invalidateDocument(docID)
	}
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

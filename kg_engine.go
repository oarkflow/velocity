package velocity

import (
	"context"
	"fmt"
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
	IngestWorkers int // concurrent workers for batch ingest (default 4)

	// HNSW tuning
	HNSWM              int // max connections per layer (default 16)
	HNSWEfConstruction int // beam width during build (default 200)
	HNSWEfSearch       int // beam width during search (default 50)
}

// KnowledgeGraphEngine is the top-level orchestrator for the KG subsystem.
type KnowledgeGraphEngine struct {
	db       *DB
	pipeline *KGIngestPipeline
	search   *KGSearchEngine
	hnsw     *HNSWIndex
	embedder KGEmbedder
	ner      KGNEREngine
	em       *EntityManager
	config   KGConfig
}

// NewKnowledgeGraphEngine creates a new KG engine wired to the given DB.
func NewKnowledgeGraphEngine(db *DB, config KGConfig) (*KnowledgeGraphEngine, error) {
	if db == nil {
		return nil, fmt.Errorf("db is required")
	}

	engine := &KnowledgeGraphEngine{
		db:     db,
		ner:    NewRuleBasedNER(),
		em:     NewEntityManager(db),
		config: config,
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
	db.SetSearchSchemaForPrefix(kgChunkSearchPrefix, &SearchSchema{
		Fields: []SearchSchemaField{{Name: "$value", Searchable: true}},
	})

	return engine, nil
}

// Ingest processes a single document.
func (e *KnowledgeGraphEngine) Ingest(ctx context.Context, req *KGIngestRequest) (*KGIngestResponse, error) {
	return e.pipeline.Ingest(ctx, req)
}

// IngestBatch processes multiple documents concurrently.
func (e *KnowledgeGraphEngine) IngestBatch(ctx context.Context, reqs []*KGIngestRequest) ([]*KGIngestResponse, []error) {
	return e.pipeline.IngestBatch(ctx, reqs)
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
	return e.pipeline.DeleteDocument(docID)
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
func (e *KnowledgeGraphEngine) GraphNeighbors(ctx context.Context, entityID string, depth int) (*EntityResult, error) {
	if depth <= 0 {
		depth = 1
	}
	results, err := e.em.GetRelatedEntities(ctx, entityID, "", depth)
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

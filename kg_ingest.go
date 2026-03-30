package velocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// IngestConfig controls pipeline behavior.
type IngestConfig struct {
	Workers       int  // concurrent workers for batch ingest (default 4)
	BatchSize     int  // embedding batch size (default 32)
	SkipDuplicate bool // skip documents with the same source (default true)
}

func (c *IngestConfig) defaults() {
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 32
	}
}

// KGIngestPipeline orchestrates the document ingest stages.
type KGIngestPipeline struct {
	db        *DB
	extractor KGExtractor
	chunker   KGChunker
	ner       KGNEREngine
	resolver  *EntityResolver
	embedder  KGEmbedder
	hnsw      *HNSWIndex
	em        *EntityManager
	config    IngestConfig
}

// NewKGIngestPipeline creates a new ingest pipeline.
func NewKGIngestPipeline(db *DB, opts ...IngestOption) *KGIngestPipeline {
	p := &KGIngestPipeline{
		db:        db,
		extractor: NewDefaultExtractor(),
		chunker:   NewSlidingWindowChunker(256, 64),
		ner:       NewRuleBasedNER(),
		resolver:  NewEntityResolver(0.85),
		em:        NewEntityManager(db),
		config:    IngestConfig{Workers: 4, BatchSize: 32, SkipDuplicate: true},
	}
	for _, opt := range opts {
		opt(p)
	}
	p.config.defaults()
	return p
}

// IngestOption configures the ingest pipeline.
type IngestOption func(*KGIngestPipeline)

func WithExtractor(e KGExtractor) IngestOption    { return func(p *KGIngestPipeline) { p.extractor = e } }
func WithChunker(c KGChunker) IngestOption         { return func(p *KGIngestPipeline) { p.chunker = c } }
func WithNER(n KGNEREngine) IngestOption           { return func(p *KGIngestPipeline) { p.ner = n } }
func WithEmbedder(e KGEmbedder) IngestOption       { return func(p *KGIngestPipeline) { p.embedder = e } }
func WithHNSW(h *HNSWIndex) IngestOption           { return func(p *KGIngestPipeline) { p.hnsw = h } }
func WithIngestConfig(c IngestConfig) IngestOption { return func(p *KGIngestPipeline) { p.config = c } }

// Ingest processes a single document through the pipeline.
func (p *KGIngestPipeline) Ingest(ctx context.Context, req *KGIngestRequest) (*KGIngestResponse, error) {
	start := time.Now()

	if req.Source == "" {
		return nil, fmt.Errorf("source is required")
	}
	if len(req.Content) == 0 {
		return nil, fmt.Errorf("content is empty")
	}
	if req.MediaType == "" {
		req.MediaType = "text/plain"
	}

	// Dedup check
	if p.config.SkipDuplicate {
		if _, err := p.db.Get([]byte(kgSourcePrefix + req.Source)); err == nil {
			return nil, fmt.Errorf("document already ingested: %s", req.Source)
		}
	}

	// Stage 1: Extract text
	text, err := p.extractor.Extract(req.Content, req.MediaType)
	if err != nil {
		return nil, fmt.Errorf("extraction failed: %w", err)
	}
	if text == "" {
		return nil, fmt.Errorf("no text extracted from content")
	}

	// Generate document ID from source + content for deterministic, collision-free IDs
	h := sha256.Sum256(append([]byte(req.Source+":"), req.Content...))
	docID := hex.EncodeToString(h[:16])

	// Stage 2: Chunk
	chunks := p.chunker.Chunk(docID, text)

	// Stage 3: NER
	var entities []KGEntity
	if p.ner != nil {
		entities = p.ner.Extract(text)
		for i := range entities {
			entities[i].DocID = docID
		}
	}

	// Stage 4: Entity resolution
	if p.resolver != nil && len(entities) > 0 {
		entities = p.resolver.Resolve(entities)
	}

	// Stage 5: Embed chunks (if embedder available)
	if p.embedder != nil && len(chunks) > 0 {
		texts := make([]string, len(chunks))
		for i, c := range chunks {
			texts[i] = c.Text
		}
		embeddings, err := p.embedder.EmbedBatch(ctx, texts)
		if err != nil {
			// Non-fatal: proceed without embeddings
			_ = err
		} else {
			for i := range chunks {
				if i < len(embeddings) {
					chunks[i].Embedding = embeddings[i]
				}
			}
		}
	}

	// Stage 6: Persist document
	checksum := sha256.Sum256(req.Content)
	now := time.Now().UTC()
	doc := KGDocument{
		ID:          docID,
		Source:      req.Source,
		MediaType:   req.MediaType,
		Title:       req.Title,
		Text:        text,
		Entities:    entities,
		Metadata:    req.Metadata,
		IngestedAt:  now,
		Checksum:    hex.EncodeToString(checksum[:]),
		ChunkCount:  len(chunks),
		EntityCount: len(entities),
	}

	// Don't store full text and chunks in the document record (they're stored separately)
	docForStorage := doc
	docForStorage.Text = ""
	docForStorage.Chunks = nil
	docForStorage.Entities = nil

	docData, err := json.Marshal(docForStorage)
	if err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}
	if err := p.db.Put([]byte(kgDocPrefix+docID), docData); err != nil {
		return nil, fmt.Errorf("store document: %w", err)
	}

	// Stage 7: Store and index chunks
	chunkSchema := &SearchSchema{
		Fields: []SearchSchemaField{{Name: "$value", Searchable: true}},
	}

	for i, chunk := range chunks {
		// Store chunk JSON for retrieval (under a separate key to avoid BM25 indexing the JSON)
		chunkData, err := json.Marshal(chunk)
		if err != nil {
			continue
		}
		// Use a non-indexed key for the chunk metadata
		metaKey := kgChunkMetaPrefix + chunk.ID
		if err := p.db.Put([]byte(metaKey), chunkData); err != nil {
			continue
		}

		// Store chunk-doc index
		p.db.Put([]byte(fmt.Sprintf("%s%s:%d", kgChunkDocPrefix, docID, i)), []byte(chunk.ID))

		// BM25 index: store raw text under the chunk key for full-text search
		chunkKey := kgChunkPrefix + chunk.ID
		p.db.PutIndexed([]byte(chunkKey), []byte(chunk.Text), chunkSchema)

		// HNSW index (if available and chunk has embedding)
		if p.hnsw != nil && len(chunk.Embedding) > 0 {
			_ = p.hnsw.Insert(chunk.ID, chunk.Embedding)
		}
	}

	// Stage 8: Entity graph — create entity nodes and document-entity relations
	if p.em != nil && len(entities) > 0 {
		p.indexEntities(ctx, docID, entities)
	}

	// Stage 9: Source index (for dedup)
	p.db.Put([]byte(kgSourcePrefix+req.Source), []byte(docID))

	// Stage 10: Update stats
	p.updateStats(len(chunks), len(entities))

	return &KGIngestResponse{
		DocID:       docID,
		ChunkCount:  len(chunks),
		EntityCount: len(entities),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

// IngestBatch processes multiple documents concurrently.
func (p *KGIngestPipeline) IngestBatch(ctx context.Context, reqs []*KGIngestRequest) ([]*KGIngestResponse, []error) {
	results := make([]*KGIngestResponse, len(reqs))
	errs := make([]error, len(reqs))

	sem := make(chan struct{}, p.config.Workers)
	var wg sync.WaitGroup

	for i, req := range reqs {
		wg.Add(1)
		go func(idx int, r *KGIngestRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := p.Ingest(ctx, r)
			results[idx] = resp
			errs[idx] = err
		}(i, req)
	}

	wg.Wait()
	return results, errs
}

func (p *KGIngestPipeline) indexEntities(ctx context.Context, docID string, entities []KGEntity) {
	seen := make(map[string]string) // canonical|type -> entityID

	for _, ent := range entities {
		key := ent.Canonical + "|" + ent.Type
		entityNodeID, exists := seen[key]

		if !exists {
			// Create entity node
			entReq := &EntityRequest{
				Type:    ent.Type,
				Name:    ent.Canonical,
				Tags:    map[string]string{"kg_type": ent.Type},
				Metadata: map[string]string{
					"surface":    ent.Surface,
					"confidence": fmt.Sprintf("%.2f", ent.Confidence),
				},
				CreatedBy: "kg-pipeline",
			}
			created, err := p.em.CreateEntity(ctx, entReq)
			if err != nil {
				continue
			}
			entityNodeID = created.EntityID
			seen[key] = entityNodeID
		}

		// Create document-entity relation
		p.em.AddRelation(ctx, &EntityRelationRequest{
			SourceEntity: docID,
			TargetEntity: entityNodeID,
			RelationType: "mentions",
			Metadata: map[string]string{
				"surface":    ent.Surface,
				"confidence": fmt.Sprintf("%.2f", ent.Confidence),
			},
			CreatedBy: "kg-pipeline",
		})
	}
}

func (p *KGIngestPipeline) updateStats(chunks, entities int) {
	statsData, _ := p.db.Get([]byte(kgStatsKey))
	var stats KGCorpusStats
	if len(statsData) > 0 {
		json.Unmarshal(statsData, &stats)
	}
	if stats.EntityTypes == nil {
		stats.EntityTypes = make(map[string]int)
	}
	stats.Documents++
	stats.Chunks += chunks
	stats.Entities += entities
	data, _ := json.Marshal(stats)
	p.db.Put([]byte(kgStatsKey), data)
}

// GetDocument retrieves a stored document by ID.
func (p *KGIngestPipeline) GetDocument(docID string) (*KGDocument, error) {
	data, err := p.db.Get([]byte(kgDocPrefix + docID))
	if err != nil {
		return nil, fmt.Errorf("document not found: %s", docID)
	}
	var doc KGDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal document: %w", err)
	}
	return &doc, nil
}

// DeleteDocument removes a document and its chunks from the index.
func (p *KGIngestPipeline) DeleteDocument(docID string) error {
	// Load document
	doc, err := p.GetDocument(docID)
	if err != nil {
		return err
	}

	// Delete chunks
	for i := 0; i < doc.ChunkCount; i++ {
		chunkIDData, err := p.db.Get([]byte(fmt.Sprintf("%s%s:%d", kgChunkDocPrefix, docID, i)))
		if err != nil {
			continue
		}
		chunkID := string(chunkIDData)
		p.db.Delete([]byte(kgChunkPrefix + chunkID))
		p.db.Delete([]byte(kgChunkMetaPrefix + chunkID))
		if p.hnsw != nil {
			p.hnsw.Delete(chunkID)
		}
	}

	// Delete document
	p.db.Delete([]byte(kgDocPrefix + docID))

	// Delete source index
	if doc.Source != "" {
		p.db.Delete([]byte(kgSourcePrefix + doc.Source))
	}

	return nil
}

// GetStats returns corpus statistics.
func (p *KGIngestPipeline) GetStats() *KGCorpusStats {
	statsData, err := p.db.Get([]byte(kgStatsKey))
	if err != nil {
		return &KGCorpusStats{EntityTypes: make(map[string]int)}
	}
	var stats KGCorpusStats
	json.Unmarshal(statsData, &stats)
	return &stats
}

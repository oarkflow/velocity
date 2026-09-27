package api

import "context"

// SearchHit is one result from SearchIndex.Query or VectorIndex.Search.
type SearchHit struct {
	Key   string
	Score float64
}

// SearchIndex is the full-text/value search surface, ported from v1's
// search_index.go (schema-based secondary indexing + tokenized query
// parsing).
type SearchIndex interface {
	Index(ctx context.Context, key string, fields map[string]any) error
	Remove(ctx context.Context, key string) error
	Query(ctx context.Context, q string, limit int) ([]SearchHit, error)
}

// VectorIndex is the vector-similarity surface, ported from v1's pkg/kg
// HNSW implementation.
type VectorIndex interface {
	Upsert(ctx context.Context, id string, vec []float32, meta map[string]any) error
	Delete(ctx context.Context, id string) error
	Search(ctx context.Context, vec []float32, k int) ([]SearchHit, error)
}

// GraphStore is the knowledge-graph surface, ported from v1's pkg/kg
// entity/relation/traversal logic.
type GraphStore interface {
	AddEntity(ctx context.Context, id string, attrs map[string]any) error
	AddRelation(ctx context.Context, from, to, relType string, attrs map[string]any) error
	Traverse(ctx context.Context, start string, depth int) ([]string, error)
}

// ExtractedEntity is one entity found in text by EntityExtractionService.
// Start/End are byte offsets into the source text (not rune offsets — a
// caller slicing text[Start:End] gets exactly the matched surface form).
type ExtractedEntity struct {
	Text  string
	Type  string
	Start int
	End   int
}

// EntityResolution is the result of merging entity IDs judged to refer to
// the same real-world entity: CanonicalID is the representative surface
// form, MergedIDs lists every input ID folded into it (including
// CanonicalID itself).
type EntityResolution struct {
	CanonicalID string
	MergedIDs   []string
}

// EntityExtractionService is a separate surface from GraphStore (not
// merged into it) because extraction/resolution/chunking are text-mining
// operations that produce candidates for the graph, not graph-storage
// operations themselves — a caller typically runs ExtractEntities, then
// AddEntity/AddRelation on a GraphStore for what it decides to keep.
// Ported from v1's pkg/kg: ExtractEntities from a regex/pattern-based NER
// engine (ner.go — not a machine-learning model), ResolveEntities from a
// Jaro-Winkler string-similarity clustering resolver (entity_resolver.go),
// ChunkText from a word-count sliding-window chunker with overlap
// (chunker.go). Service name: "search.entities" ->
// api.EntityExtractionService.
type EntityExtractionService interface {
	// ExtractEntities finds entities in text via pattern/regex rules
	// (email, URL, date, money, phone, person/org name patterns, and
	// several ID-like formats — see the plugin's rule list for the exact
	// set). This is deliberately not a machine-learning NER model; v1
	// never had one either.
	ExtractEntities(ctx context.Context, text string) ([]ExtractedEntity, error)

	// ResolveEntities clusters entityIDs whose surface forms are
	// Jaro-Winkler similar above a configured threshold (default 0.85,
	// matching v1), picks the most frequent surface form in each cluster
	// as canonical, and returns one EntityResolution per cluster.
	ResolveEntities(ctx context.Context, entityIDs []string) ([]EntityResolution, error)

	// ChunkText splits text into overlapping chunks using a word-count
	// sliding window (maxWords words per chunk, a fixed overlap between
	// consecutive chunks) — not byte/character size and not
	// sentence-boundary detection, matching v1's real SlidingWindowChunker
	// faithfully rather than a more sophisticated scheme it never had.
	ChunkText(ctx context.Context, text string, maxWords int) ([]string, error)
}

package velocity

import "time"

// LSM key prefix constants for Knowledge Graph data
const (
	kgPrefix         = "__kg"
	kgDocPrefix      = "__kg:doc:"
	kgChunkPrefix    = "__kg:chunk:"
	kgChunkMetaPrefix = "__kgm:chunk:" // separate prefix to avoid BM25 auto-indexing
	kgChunkDocPrefix = "__kg:chunkdoc:"
	kgEntityPrefix   = "__kg:entity:"
	kgVecPrefix      = "__kg:vec:"
	kgHNSWPrefix     = "__kg:hnsw:"
	kgHNSWMeta       = "__kg:hnsw:meta"
	kgSourcePrefix   = "__kg:src:"
	kgStatsKey       = "__kg:stats"
	// kgChunkSearchPrefix is used for BM25 index registration. It must NOT
	// include a trailing colon so that prefixMatch (search_index.go) accepts
	// keys like "__kg:chunk:xxx" where the first char after the prefix is ':'.
	kgChunkSearchPrefix = "__kg:chunk"
)

// KGDocument represents a document ingested into the knowledge graph.
type KGDocument struct {
	ID        string            `json:"id"`
	Source    string            `json:"source"`
	MediaType string           `json:"media_type"`
	Title     string            `json:"title,omitempty"`
	Text      string            `json:"text"`
	Chunks    []KGChunk         `json:"chunks,omitempty"`
	Entities  []KGEntity        `json:"entities,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	IngestedAt time.Time        `json:"ingested_at"`
	UpdatedAt  time.Time        `json:"updated_at,omitempty"`
	Checksum   string           `json:"checksum"`
	ChunkCount int              `json:"chunk_count"`
	EntityCount int             `json:"entity_count"`
}

// KGChunk represents a text chunk from a document.
type KGChunk struct {
	ID        string    `json:"id"`
	DocID     string    `json:"doc_id"`
	Index     int       `json:"index"`
	Text      string    `json:"text"`
	Embedding []float32 `json:"embedding,omitempty"`
	StartByte int       `json:"start_byte"`
	EndByte   int       `json:"end_byte"`
}

// KGEntity represents a named entity extracted from text.
type KGEntity struct {
	Surface    string  `json:"surface"`
	Canonical  string  `json:"canonical"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	DocID      string  `json:"doc_id,omitempty"`
	ChunkID    string  `json:"chunk_id,omitempty"`
	StartByte  int     `json:"start_byte,omitempty"`
	EndByte    int     `json:"end_byte,omitempty"`
}

// SearchMode represents the type of search to perform.
type KGSearchMode string

const (
	KGSearchModeKeyword  KGSearchMode = "keyword"
	KGSearchModeSemantic KGSearchMode = "semantic"
	KGSearchModeHybrid   KGSearchMode = "hybrid"
)

// KGSearchRequest represents a search query.
type KGSearchRequest struct {
	Query        string            `json:"query"`
	Limit        int               `json:"limit,omitempty"`
	MinScore     float64           `json:"min_score,omitempty"`
	Filters      map[string]string `json:"filters,omitempty"`
	Mode         KGSearchMode      `json:"mode,omitempty"`
	EnableVector bool              `json:"enable_vector,omitempty"`
	EnableGraph  bool              `json:"enable_graph,omitempty"`
	GraphDepth   int               `json:"graph_depth,omitempty"`
	BM25Weight   float64           `json:"bm25_weight,omitempty"`
	VectorWeight float64           `json:"vector_weight,omitempty"`
}

// KGSearchHit represents a single search result hit.
type KGSearchHit struct {
	ChunkID   string            `json:"chunk_id"`
	DocID     string            `json:"doc_id"`
	Text      string            `json:"text"`
	Score     float64           `json:"score"`
	BM25Score float64           `json:"bm25_score,omitempty"`
	VecScore  float64           `json:"vec_score,omitempty"`
	Source    string            `json:"source,omitempty"`
	Title     string            `json:"title,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Entities  []KGEntity        `json:"entities,omitempty"`
}

// KGSearchResponse is the response from a search query.
type KGSearchResponse struct {
	Hits        []KGSearchHit `json:"hits"`
	TotalHits   int           `json:"total_hits"`
	QueryTimeMs int64         `json:"query_time_ms"`
	Mode        KGSearchMode  `json:"mode"`
	GraphNodes  int           `json:"graph_nodes,omitempty"`
}

// KGIngestRequest represents a request to ingest a document.
type KGIngestRequest struct {
	Source    string            `json:"source"`
	Content  []byte            `json:"content"`
	MediaType string           `json:"media_type"`
	Title     string            `json:"title,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// KGIngestResponse is the response after ingesting a document.
type KGIngestResponse struct {
	DocID       string `json:"doc_id"`
	ChunkCount  int    `json:"chunk_count"`
	EntityCount int    `json:"entity_count"`
	DurationMs  int64  `json:"duration_ms"`
}

// KGAnalytics contains corpus statistics.
type KGAnalytics struct {
	TotalDocuments int            `json:"total_documents"`
	TotalChunks    int            `json:"total_chunks"`
	TotalEntities  int            `json:"total_entities"`
	EntityTypes    map[string]int `json:"entity_types,omitempty"`
	TopEntities    []KGEntityStat `json:"top_entities,omitempty"`
}

// KGEntityStat represents entity frequency statistics.
type KGEntityStat struct {
	Canonical string `json:"canonical"`
	Type      string `json:"type"`
	Count     int    `json:"count"`
}

// KGCorpusStats is stored in the LSM-tree for tracking.
type KGCorpusStats struct {
	Documents int            `json:"documents"`
	Chunks    int            `json:"chunks"`
	Entities  int            `json:"entities"`
	EntityTypes map[string]int `json:"entity_types,omitempty"`
}

// ScoredChunk is used internally for ranking.
type ScoredChunk struct {
	ChunkID string
	Score   float64
	Rank    int
}

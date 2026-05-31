package kg

import (
	"context"
	"time"
)

type ResourceType string

const (
	ResourceKV       ResourceType = "kv"
	ResourceObject   ResourceType = "object"
	ResourceSecret   ResourceType = "secret"
	ResourceSQLRow   ResourceType = "sql_row"
	ResourceEnvelope ResourceType = "envelope"
	ResourceEntity   ResourceType = "entity"
)

// KGAuthzResource is the authorization context for a KG result or mutation.
type KGAuthzResource struct {
	Kind         string            `json:"kind"`
	ID           string            `json:"id,omitempty"`
	Source       string            `json:"source,omitempty"`
	Target       string            `json:"target,omitempty"`
	ResourceType ResourceType      `json:"resource_type,omitempty"`
	RelationType string            `json:"relation_type,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// KGAuthzFilter is an optional host-provided visibility hook. Return false to
// remove the item from search/graph results or deny explicit graph mutations.
type KGAuthzFilter func(ctx context.Context, resource KGAuthzResource) bool

// LSM key prefix constants for Knowledge Graph data
const (
	kgDocPrefix       = "__kg:doc:"
	kgChunkPrefix     = "__kg:chunk:"
	kgChunkMetaPrefix = "__kgm:chunk:" // separate prefix to avoid BM25 auto-indexing
	kgChunkDocPrefix  = "__kg:chunkdoc:"
	kgVecPrefix       = "__kg:vec:"
	kgHNSWPrefix      = "__kg:hnsw:"
	kgHNSWMeta        = "__kg:hnsw:meta"
	kgSourcePrefix    = "__kg:src:"
	kgStatsKey        = "__kg:stats"
	kgRelationPrefix  = "__kg:rel:"
	kgOntologyPrefix  = "__kg:ont:"
	kgAliasPrefix     = "__kg:alias:"
	kgMergePrefix     = "__kg:merge:"
	kgJobPrefix       = "__kg:job:"
	kgMutationPrefix  = "__kg:mut:"
	// kgChunkSearchPrefix is used for BM25 index registration. It must NOT
	// include a trailing colon so that prefixMatch (search_index.go) accepts
	// keys like "__kg:chunk:xxx" where the first char after the prefix is ':'.
	kgChunkSearchPrefix = "__kg:chunk"
)

// KGDocument represents a document ingested into the knowledge graph.
type KGDocument struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`
	MediaType   string            `json:"media_type"`
	Title       string            `json:"title,omitempty"`
	Text        string            `json:"text"`
	Chunks      []KGChunk         `json:"chunks,omitempty"`
	Entities    []KGEntity        `json:"entities,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	IngestedAt  time.Time         `json:"ingested_at"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	Checksum    string            `json:"checksum"`
	ChunkCount  int               `json:"chunk_count"`
	EntityCount int               `json:"entity_count"`
}

// KGChunk represents a text chunk from a document.
type KGChunk struct {
	ID        string     `json:"id"`
	DocID     string     `json:"doc_id"`
	Index     int        `json:"index"`
	Text      string     `json:"text"`
	Embedding []float32  `json:"embedding,omitempty"`
	Entities  []KGEntity `json:"entities,omitempty"`
	StartByte int        `json:"start_byte"`
	EndByte   int        `json:"end_byte"`
}

// KGEntity represents a named entity extracted from text.
type KGEntity struct {
	Surface      string            `json:"surface"`
	Canonical    string            `json:"canonical"`
	Type         string            `json:"type"`
	Confidence   float64           `json:"confidence"`
	DocID        string            `json:"doc_id,omitempty"`
	ChunkID      string            `json:"chunk_id,omitempty"`
	StartByte    int               `json:"start_byte,omitempty"`
	EndByte      int               `json:"end_byte,omitempty"`
	Aliases      []string          `json:"aliases,omitempty"`
	Identifiers  map[string]string `json:"identifiers,omitempty"`
	SourceRefs   []KGSourceRef     `json:"source_refs,omitempty"`
	CanonicalKey string            `json:"canonical_key,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

// KGSourceRef identifies where an entity or relation was observed.
type KGSourceRef struct {
	Source       string       `json:"source,omitempty"`
	DocID        string       `json:"doc_id,omitempty"`
	ChunkID      string       `json:"chunk_id,omitempty"`
	ResourceType ResourceType `json:"resource_type,omitempty"`
	ResourceID   string       `json:"resource_id,omitempty"`
	StartByte    int          `json:"start_byte,omitempty"`
	EndByte      int          `json:"end_byte,omitempty"`
}

// KGRelationDirection describes how a relation should be traversed.
type KGRelationDirection string

const (
	KGRelationDirectionOut  KGRelationDirection = "out"
	KGRelationDirectionIn   KGRelationDirection = "in"
	KGRelationDirectionBoth KGRelationDirection = "both"
)

// KGRelationStatus captures lifecycle state for persistent graph edges.
type KGRelationStatus string

const (
	KGRelationStatusActive  KGRelationStatus = "active"
	KGRelationStatusPending KGRelationStatus = "pending"
	KGRelationStatusDeleted KGRelationStatus = "deleted"
)

// KGRelation describes an inferred or explicit graph edge with explainable evidence.
type KGRelation struct {
	RelationID   string              `json:"relation_id,omitempty"`
	Source       string              `json:"source"`
	Target       string              `json:"target"`
	RelationType string              `json:"relation_type"`
	Direction    KGRelationDirection `json:"direction,omitempty"`
	Confidence   float64             `json:"confidence,omitempty"`
	Evidence     string              `json:"evidence,omitempty"`
	SourceKind   string              `json:"source_kind,omitempty"`
	SourceRefs   []KGSourceRef       `json:"source_refs,omitempty"`
	Status       KGRelationStatus    `json:"status,omitempty"`
	CreatedBy    string              `json:"created_by,omitempty"`
	CreatedAt    time.Time           `json:"created_at,omitempty"`
	UpdatedAt    time.Time           `json:"updated_at,omitempty"`
	Revision     int64               `json:"revision,omitempty"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
	Attributes   map[string]string   `json:"attributes,omitempty"`
}

// KGRelationRequest creates an explicit persistent graph relation.
type KGRelationRequest struct {
	RelationID   string              `json:"relation_id,omitempty"`
	Source       string              `json:"source"`
	Target       string              `json:"target"`
	RelationType string              `json:"relation_type"`
	Direction    KGRelationDirection `json:"direction,omitempty"`
	Confidence   float64             `json:"confidence,omitempty"`
	Evidence     string              `json:"evidence,omitempty"`
	SourceKind   string              `json:"source_kind,omitempty"`
	SourceRefs   []KGSourceRef       `json:"source_refs,omitempty"`
	Status       KGRelationStatus    `json:"status,omitempty"`
	CreatedBy    string              `json:"created_by,omitempty"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
	Attributes   map[string]string   `json:"attributes,omitempty"`
}

// KGRelationUpdate changes mutable relation metadata while preserving identity.
type KGRelationUpdate struct {
	Target       *string              `json:"target,omitempty"`
	RelationType *string              `json:"relation_type,omitempty"`
	Direction    *KGRelationDirection `json:"direction,omitempty"`
	Confidence   *float64             `json:"confidence,omitempty"`
	Evidence     *string              `json:"evidence,omitempty"`
	SourceKind   *string              `json:"source_kind,omitempty"`
	SourceRefs   []KGSourceRef        `json:"source_refs,omitempty"`
	Status       *KGRelationStatus    `json:"status,omitempty"`
	Metadata     map[string]string    `json:"metadata,omitempty"`
	Attributes   map[string]string    `json:"attributes,omitempty"`
	UpdatedBy    string               `json:"updated_by,omitempty"`
}

// KGRelationQuery filters persistent relations.
type KGRelationQuery struct {
	RelationID     string              `json:"relation_id,omitempty"`
	Source         string              `json:"source,omitempty"`
	Target         string              `json:"target,omitempty"`
	RelationTypes  []string            `json:"relation_types,omitempty"`
	Direction      KGRelationDirection `json:"direction,omitempty"`
	Status         KGRelationStatus    `json:"status,omitempty"`
	MinConfidence  float64             `json:"min_confidence,omitempty"`
	SourceKind     string              `json:"source_kind,omitempty"`
	Limit          int                 `json:"limit,omitempty"`
	IncludeDeleted bool                `json:"include_deleted,omitempty"`
}

// KGOntology defines optional production constraints for graph data.
type KGOntology struct {
	Name          string                            `json:"name"`
	Version       string                            `json:"version,omitempty"`
	NodeTypes     map[string]KGOntologyNodeType     `json:"node_types,omitempty"`
	RelationTypes map[string]KGOntologyRelationType `json:"relation_types,omitempty"`
	CreatedAt     time.Time                         `json:"created_at,omitempty"`
	UpdatedAt     time.Time                         `json:"updated_at,omitempty"`
}

// KGOntologyNodeType describes node requirements. Nodes are currently implicit.
type KGOntologyNodeType struct {
	Type           string   `json:"type"`
	RequiredFields []string `json:"required_fields,omitempty"`
	UniqueKeys     []string `json:"unique_keys,omitempty"`
}

// KGOntologyRelationType constrains an edge type.
type KGOntologyRelationType struct {
	Type                 string              `json:"type"`
	AllowedSources       []string            `json:"allowed_sources,omitempty"`
	AllowedTargets       []string            `json:"allowed_targets,omitempty"`
	Direction            KGRelationDirection `json:"direction,omitempty"`
	RequiredFields       []string            `json:"required_fields,omitempty"`
	MaxOutgoingPerSource int                 `json:"max_outgoing_per_source,omitempty"`
	MaxIncomingPerTarget int                 `json:"max_incoming_per_target,omitempty"`
}

// KGOntologyValidationResult reports whether an ontology or relation is valid.
type KGOntologyValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// KGGraphQuery requests traversal over persistent relations.
type KGGraphQuery struct {
	SeedIDs         []string            `json:"seed_ids,omitempty"`
	SeedSearch      string              `json:"seed_search,omitempty"`
	SeedSearchLimit int                 `json:"seed_search_limit,omitempty"`
	RelationTypes   []string            `json:"relation_types,omitempty"`
	Depth           int                 `json:"depth,omitempty"`
	Direction       KGRelationDirection `json:"direction,omitempty"`
	MinConfidence   float64             `json:"min_confidence,omitempty"`
	SourceKind      string              `json:"source_kind,omitempty"`
	Limit           int                 `json:"limit,omitempty"`
}

// KGGraphNode is an implicit graph node discovered through persistent relations.
type KGGraphNode struct {
	ID         string            `json:"id"`
	NodeType   string            `json:"node_type,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// KGGraphResponse returns persistent graph query results.
type KGGraphResponse struct {
	Nodes       []KGGraphNode `json:"nodes"`
	Relations   []KGRelation  `json:"relations"`
	QueryTimeMs int64         `json:"query_time_ms"`
}

// KGMaterializeRelationsRequest persists inferred resource graph edges as
// first-class relations.
type KGMaterializeRelationsRequest struct {
	ResourceGraph KGResourceGraphRequest `json:"resource_graph"`
	CreatedBy     string                 `json:"created_by,omitempty"`
	Overwrite     bool                   `json:"overwrite,omitempty"`
	DryRun        bool                   `json:"dry_run,omitempty"`
}

// KGMaterializeRelationsResponse summarizes inferred-edge materialization.
type KGMaterializeRelationsResponse struct {
	Graph       *KGResourceGraphResponse `json:"graph,omitempty"`
	Relations   []KGRelation             `json:"relations,omitempty"`
	Created     int                      `json:"created"`
	Updated     int                      `json:"updated"`
	Skipped     int                      `json:"skipped"`
	Errors      []string                 `json:"errors,omitempty"`
	QueryTimeMs int64                    `json:"query_time_ms"`
	DryRun      bool                     `json:"dry_run,omitempty"`
}

// KGGraphPath is a sequence of nodes and relations.
type KGGraphPath struct {
	Nodes     []string     `json:"nodes"`
	Relations []KGRelation `json:"relations"`
}

// KGGraphMetrics summarizes graph structure.
type KGGraphMetrics struct {
	NodeCount       int            `json:"node_count"`
	RelationCount   int            `json:"relation_count"`
	DegreeByNode    map[string]int `json:"degree_by_node,omitempty"`
	OutDegreeByNode map[string]int `json:"out_degree_by_node,omitempty"`
	InDegreeByNode  map[string]int `json:"in_degree_by_node,omitempty"`
}

// KGMutationLogRecord is an idempotent graph mutation entry for replay/rebuild hooks.
type KGMutationLogRecord struct {
	MutationID string    `json:"mutation_id"`
	Action     string    `json:"action"`
	Entity     string    `json:"entity"`
	EntityID   string    `json:"entity_id"`
	CreatedAt  time.Time `json:"created_at"`
	Actor      string    `json:"actor,omitempty"`
	Revision   int64     `json:"revision,omitempty"`
}

// KGEntityAliasRecord redirects an alias or stale entity ID to a canonical ID.
type KGEntityAliasRecord struct {
	Alias       string            `json:"alias"`
	CanonicalID string            `json:"canonical_id"`
	Reason      string            `json:"reason,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// KGMergeStatus captures human approval state for entity merge proposals.
type KGMergeStatus string

const (
	KGMergeStatusPending  KGMergeStatus = "pending"
	KGMergeStatusApproved KGMergeStatus = "approved"
	KGMergeStatusRejected KGMergeStatus = "rejected"
)

// KGMergeProposal records a pending/approved/rejected entity canonicalization.
type KGMergeProposal struct {
	ProposalID string            `json:"proposal_id"`
	SourceIDs  []string          `json:"source_ids"`
	TargetID   string            `json:"target_id"`
	Reason     string            `json:"reason,omitempty"`
	Status     KGMergeStatus     `json:"status"`
	CreatedBy  string            `json:"created_by,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	ReviewedBy string            `json:"reviewed_by,omitempty"`
	ReviewedAt time.Time         `json:"reviewed_at,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// KGEntityMergeRequest merges one or more source entity IDs into a target ID.
type KGEntityMergeRequest struct {
	SourceIDs  []string          `json:"source_ids"`
	TargetID   string            `json:"target_id"`
	Reason     string            `json:"reason,omitempty"`
	CreatedBy  string            `json:"created_by,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
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
	Query         string            `json:"query"`
	Limit         int               `json:"limit,omitempty"`
	MinScore      float64           `json:"min_score,omitempty"`
	Filters       map[string]string `json:"filters,omitempty"`
	Mode          KGSearchMode      `json:"mode,omitempty"`
	MatchMode     string            `json:"match_mode,omitempty"`
	PrefixMatch   bool              `json:"prefix_match,omitempty"`
	Fuzzy         bool              `json:"fuzzy,omitempty"`
	FuzzyMaxEdits int               `json:"fuzzy_max_edits,omitempty"`
	EnableVector  bool              `json:"enable_vector,omitempty"`
	EnableGraph   bool              `json:"enable_graph,omitempty"`
	GraphDepth    int               `json:"graph_depth,omitempty"`
	BM25Weight    float64           `json:"bm25_weight,omitempty"`
	VectorWeight  float64           `json:"vector_weight,omitempty"`
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

// KGResourceGraphRequest asks the KG to search resources and infer a relation graph
// between the matching Velocity resources.
type KGResourceGraphRequest struct {
	Query         string            `json:"query"`
	Limit         int               `json:"limit,omitempty"`
	Depth         int               `json:"depth,omitempty"`
	Filters       map[string]string `json:"filters,omitempty"`
	Mode          KGSearchMode      `json:"mode,omitempty"`
	MatchMode     string            `json:"match_mode,omitempty"`
	PrefixMatch   bool              `json:"prefix_match,omitempty"`
	Fuzzy         bool              `json:"fuzzy,omitempty"`
	FuzzyMaxEdits int               `json:"fuzzy_max_edits,omitempty"`
	MinScore      float64           `json:"min_score,omitempty"`
	MinShared     int               `json:"min_shared,omitempty"`
	IncludeRaw    bool              `json:"include_raw,omitempty"`
}

// KGResourceGraphNode is a Velocity resource that matched a KG query.
type KGResourceGraphNode struct {
	ID           string            `json:"id"`
	Source       string            `json:"source"`
	ResourceType ResourceType      `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Title        string            `json:"title,omitempty"`
	Snippet      string            `json:"snippet,omitempty"`
	Score        float64           `json:"score,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Entities     []KGEntity        `json:"entities,omitempty"`
}

// KGResourceGraphEdge links two matching resources through an inferred relation.
type KGResourceGraphEdge struct {
	Source       string            `json:"source"`
	Target       string            `json:"target"`
	RelationType string            `json:"relation_type"`
	Entity       KGEntity          `json:"entity"`
	Weight       float64           `json:"weight"`
	Confidence   float64           `json:"confidence,omitempty"`
	Evidence     string            `json:"evidence,omitempty"`
	SourceKind   string            `json:"source_kind,omitempty"`
	CreatedBy    string            `json:"created_by,omitempty"`
	CreatedAt    time.Time         `json:"created_at,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// KGResourceGraphResponse returns query hits as a resource relation graph.
type KGResourceGraphResponse struct {
	Query       string                `json:"query"`
	Nodes       []KGResourceGraphNode `json:"nodes"`
	Edges       []KGResourceGraphEdge `json:"edges"`
	SearchHits  int                   `json:"search_hits"`
	QueryTimeMs int64                 `json:"query_time_ms"`
	Mode        KGSearchMode          `json:"mode"`
}

// KGIngestRequest represents a request to ingest a document.
type KGIngestRequest struct {
	Source    string            `json:"source"`
	Content   []byte            `json:"content"`
	MediaType string            `json:"media_type"`
	Title     string            `json:"title,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// KGCustomNERRule configures an additional rule-based entity extractor.
type KGCustomNERRule struct {
	Type       string  `json:"type"`
	Pattern    string  `json:"pattern"`
	Confidence float64 `json:"confidence,omitempty"`
}

// KGConnectorItem identifies a source record exposed by a connector.
type KGConnectorItem struct {
	Source       string            `json:"source"`
	ResourceType ResourceType      `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	MediaType    string            `json:"media_type,omitempty"`
	Title        string            `json:"title,omitempty"`
	Content      []byte            `json:"content,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Cursor       string            `json:"cursor,omitempty"`
}

// KGConnector provides a dependency-light ingestion integration point. Built-in
// and application connectors can list items and fetch them as KG ingest requests.
type KGConnector interface {
	Name() string
	ResourceType() ResourceType
	List(ctx context.Context, cursor string) ([]KGConnectorItem, string, error)
	Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error)
}

// KGWatchConnector is optionally implemented by connectors that can stream
// incremental updates.
type KGWatchConnector interface {
	Watch(ctx context.Context, cursor string) (<-chan KGConnectorItem, error)
}

// KGConnectorImportResponse summarizes a connector-driven ingest run.
type KGConnectorImportResponse struct {
	Connector  string              `json:"connector"`
	Imported   int                 `json:"imported"`
	Skipped    int                 `json:"skipped"`
	NextCursor string              `json:"next_cursor,omitempty"`
	Results    []*KGIngestResponse `json:"results,omitempty"`
	Errors     []string            `json:"errors,omitempty"`
}

// KGImportJobStatus describes persistent connector import job lifecycle.
type KGImportJobStatus string

const (
	KGImportJobPending   KGImportJobStatus = "pending"
	KGImportJobRunning   KGImportJobStatus = "running"
	KGImportJobSucceeded KGImportJobStatus = "succeeded"
	KGImportJobFailed    KGImportJobStatus = "failed"
	KGImportJobCancelled KGImportJobStatus = "cancelled"
)

// KGImportJob records operational status for connector imports.
type KGImportJob struct {
	JobID        string            `json:"job_id"`
	Connector    string            `json:"connector"`
	ResourceType ResourceType      `json:"resource_type,omitempty"`
	Cursor       string            `json:"cursor,omitempty"`
	NextCursor   string            `json:"next_cursor,omitempty"`
	Limit        int               `json:"limit,omitempty"`
	Status       KGImportJobStatus `json:"status"`
	RetryCount   int               `json:"retry_count,omitempty"`
	Imported     int               `json:"imported,omitempty"`
	Skipped      int               `json:"skipped,omitempty"`
	Errors       []string          `json:"errors,omitempty"`
	Metrics      map[string]int64  `json:"metrics,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	StartedAt    time.Time         `json:"started_at,omitempty"`
	FinishedAt   time.Time         `json:"finished_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
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
	Documents   int            `json:"documents"`
	Chunks      int            `json:"chunks"`
	Entities    int            `json:"entities"`
	EntityTypes map[string]int `json:"entity_types,omitempty"`
}

// ScoredChunk is used internally for ranking.
type ScoredChunk struct {
	ChunkID string
	Score   float64
	Rank    int
}

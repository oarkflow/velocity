package kg

import (
	"context"
	"time"
)

// Store is the minimal persistence surface required by the knowledge graph.
// The root velocity.DB implements this through a small adapter so pkg/kg stays
// independent from the root package and avoids import cycles.
type Store interface {
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	Keys(pattern string) ([]string, error)
	PutIndexedText(key, value []byte) error
	DeleteIndexed(key []byte) error
	RegisterChunkSearchPrefix(prefix string)
}

// EntityStore is the optional entity graph surface used by KG ingestion and
// graph expansion. Applications can provide a no-op implementation when they
// only need document/chunk search.
type EntityStore interface {
	CreateEntity(ctx context.Context, req *EntityRequest) (*Entity, error)
	AddRelation(ctx context.Context, req *EntityRelationRequest) (*EntityRelation, error)
	GetRelatedEntities(ctx context.Context, entityID string, relationType string, depth int) ([]*EntityResult, error)
}

// EntityDeleteStore is optionally implemented by entity stores that can delete
// KG-owned document nodes and their attached relations.
type EntityDeleteStore interface {
	DeleteEntity(ctx context.Context, entityID string) error
}

type noopEntityStore struct{}

func (noopEntityStore) CreateEntity(context.Context, *EntityRequest) (*Entity, error) {
	return nil, nil
}

func (noopEntityStore) AddRelation(context.Context, *EntityRelationRequest) (*EntityRelation, error) {
	return nil, nil
}

func (noopEntityStore) GetRelatedEntities(context.Context, string, string, int) ([]*EntityResult, error) {
	return nil, nil
}

func isNoopEntityStore(em EntityStore) bool {
	if em == nil {
		return true
	}
	_, ok := em.(noopEntityStore)
	return ok
}

// Entity mirrors the lightweight entity shape needed by the KG package.
type Entity struct {
	EntityID  string            `json:"entity_id"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Tags      map[string]string `json:"tags,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedBy string            `json:"created_by,omitempty"`
}

type EntityRequest struct {
	Type      string
	Name      string
	Tags      map[string]string
	Metadata  map[string]string
	CreatedBy string
}

type EntityRelation struct {
	RelationID    string            `json:"relation_id"`
	SourceEntity  string            `json:"source_entity"`
	TargetEntity  string            `json:"target_entity"`
	RelationType  string            `json:"relation_type"`
	CreatedAt     time.Time         `json:"created_at,omitempty"`
	CreatedBy     string            `json:"created_by,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Bidirectional bool              `json:"bidirectional"`
}

type EntityRelationRequest struct {
	SourceEntity  string
	TargetEntity  string
	RelationType  string
	Bidirectional bool
	Metadata      map[string]string
	CreatedBy     string
}

type EntityResult struct {
	Entity        *Entity           `json:"entity"`
	Relationships []*EntityRelation `json:"relationships,omitempty"`
	DataRedacted  bool              `json:"data_redacted"`
}

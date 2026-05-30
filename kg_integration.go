package velocity

import (
	"context"

	"github.com/oarkflow/velocity/pkg/kg"
)

// PutIndexedText lets *DB satisfy kg.Store directly.
func (db *DB) PutIndexedText(key, value []byte) error {
	return db.PutIndexed(key, value, &SearchSchema{Fields: []SearchSchemaField{{Name: "$value", Searchable: true}}})
}

// RegisterChunkSearchPrefix lets *DB satisfy kg.Store directly.
func (db *DB) RegisterChunkSearchPrefix(prefix string) {
	db.SetSearchSchemaForPrefix(prefix, &SearchSchema{Fields: []SearchSchemaField{{Name: "$value", Searchable: true}}})
}

type kgEntityAdapter struct {
	db *DB
}

func (a kgEntityAdapter) CreateEntity(ctx context.Context, req *kg.EntityRequest) (*kg.Entity, error) {
	entity, err := a.db.CreateEntity(ctx, &EntityRequest{
		Type:      req.Type,
		Name:      req.Name,
		Tags:      req.Tags,
		Metadata:  req.Metadata,
		CreatedBy: req.CreatedBy,
	})
	if err != nil {
		return nil, err
	}
	return &kg.Entity{
		EntityID:  entity.EntityID,
		Type:      entity.Type,
		Name:      entity.Name,
		Tags:      entity.Tags,
		Metadata:  entity.Metadata,
		CreatedBy: entity.CreatedBy,
	}, nil
}

func (a kgEntityAdapter) AddRelation(ctx context.Context, req *kg.EntityRelationRequest) (*kg.EntityRelation, error) {
	rel, err := a.db.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity:  req.SourceEntity,
		TargetEntity:  req.TargetEntity,
		RelationType:  req.RelationType,
		Bidirectional: req.Bidirectional,
		Metadata:      req.Metadata,
		CreatedBy:     req.CreatedBy,
	})
	if err != nil {
		return nil, err
	}
	return &kg.EntityRelation{
		RelationID:    rel.RelationID,
		SourceEntity:  rel.SourceEntity,
		TargetEntity:  rel.TargetEntity,
		RelationType:  rel.RelationType,
		CreatedAt:     rel.CreatedAt,
		CreatedBy:     rel.CreatedBy,
		Metadata:      rel.Metadata,
		Bidirectional: rel.Bidirectional,
	}, nil
}

func (a kgEntityAdapter) GetRelatedEntities(ctx context.Context, entityID string, relationType string, depth int) ([]*kg.EntityResult, error) {
	results, err := a.db.GetRelatedEntities(ctx, entityID, relationType, depth)
	if err != nil {
		return nil, err
	}
	out := make([]*kg.EntityResult, 0, len(results))
	for _, result := range results {
		if result == nil {
			continue
		}
		item := &kg.EntityResult{DataRedacted: result.DataRedacted}
		if result.Entity != nil {
			item.Entity = &kg.Entity{
				EntityID:  result.Entity.EntityID,
				Type:      result.Entity.Type,
				Name:      result.Entity.Name,
				Tags:      result.Entity.Tags,
				Metadata:  result.Entity.Metadata,
				CreatedBy: result.Entity.CreatedBy,
			}
		}
		for _, rel := range result.Relationships {
			item.Relationships = append(item.Relationships, &kg.EntityRelation{
				RelationID:    rel.RelationID,
				SourceEntity:  rel.SourceEntity,
				TargetEntity:  rel.TargetEntity,
				RelationType:  rel.RelationType,
				CreatedAt:     rel.CreatedAt,
				CreatedBy:     rel.CreatedBy,
				Metadata:      rel.Metadata,
				Bidirectional: rel.Bidirectional,
			})
		}
		out = append(out, item)
	}
	return out, nil
}

func (a kgEntityAdapter) DeleteEntity(ctx context.Context, entityID string) error {
	return a.db.DeleteEntity(ctx, entityID)
}

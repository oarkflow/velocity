package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func setupEntityTestDB(t *testing.T) (*DB, func()) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

func TestEntityManager_CreateEntity(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Test creating a JSON entity
	jsonData := json.RawMessage(`{"name": "test", "value": 123}`)
	req := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "test-entity",
		Data:      jsonData,
		CreatedBy: "test-user",
		Tags:      map[string]string{"env": "test"},
	}

	entity, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	if entity.EntityID == "" {
		t.Error("Entity ID should not be empty")
	}
	if entity.Type != EntityTypeJSON {
		t.Errorf("Expected type %s, got %s", EntityTypeJSON, entity.Type)
	}
	if entity.Name != "test-entity" {
		t.Errorf("Expected name 'test-entity', got %s", entity.Name)
	}
	if entity.Version != 1 {
		t.Errorf("Expected version 1, got %d", entity.Version)
	}
	if entity.Checksum == "" {
		t.Error("Checksum should not be empty")
	}
}

func TestEntityManager_CreateEntityWithSecret(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Store a secret first
	secretKey := []byte("secret:api-key")
	secretValue := []byte("secret-api-key-value")
	if err := db.Put(secretKey, secretValue); err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Create entity referencing the secret
	req := &EntityRequest{
		Type:      EntityTypeSecret,
		Name:      "api-credentials",
		SecretRef: "api-key",
		CreatedBy: "test-user",
	}

	entity, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	if entity.SecretRef != "api-key" {
		t.Errorf("Expected secret ref 'api-key', got %s", entity.SecretRef)
	}
}

func TestEntityManager_CreateEntityWithObject(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Store an object first
	objectData := []byte("test object data")
	meta, err := db.StoreObject("test/file.txt", "text/plain", "test-user", objectData, &ObjectOptions{
		Encrypt: false,
	})
	if err != nil {
		t.Fatalf("Failed to store object: %v", err)
	}

	// Create entity referencing the object
	req := &EntityRequest{
		Type:       EntityTypeObject,
		Name:       "test-file-entity",
		ObjectPath: meta.Path,
		CreatedBy:  "test-user",
	}

	entity, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	if entity.ObjectPath != meta.Path {
		t.Errorf("Expected object path %s, got %s", meta.Path, entity.ObjectPath)
	}
}

func TestEntityManager_GetEntity(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create an entity
	jsonData := json.RawMessage(`{"test": "data"}`)
	req := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "get-test-entity",
		Data:      jsonData,
		CreatedBy: "test-user",
	}

	created, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Get the entity without relations
	result, err := em.GetEntity(ctx, created.EntityID, false)
	if err != nil {
		t.Fatalf("Failed to get entity: %v", err)
	}

	if result.Entity.EntityID != created.EntityID {
		t.Errorf("Expected entity ID %s, got %s", created.EntityID, result.Entity.EntityID)
	}
	if result.Relationships != nil {
		t.Error("Relationships should be nil when includeRelations is false")
	}

	// Get the entity with relations
	resultWithRelations, err := em.GetEntity(ctx, created.EntityID, true)
	if err != nil {
		t.Fatalf("Failed to get entity with relations: %v", err)
	}

	if resultWithRelations.Relationships == nil {
		t.Error("Relationships should not be nil when includeRelations is true")
	}
}

func TestEntityManager_UpdateEntity(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create an entity
	jsonData := json.RawMessage(`{"version": 1}`)
	req := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "update-test-entity",
		Data:      jsonData,
		CreatedBy: "test-user",
	}

	created, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Update the entity
	updatedData := json.RawMessage(`{"version": 2}`)
	updateReq := &EntityRequest{
		Name:      "updated-entity-name",
		Data:      updatedData,
		CreatedBy:  "update-user",
	}

	updated, err := em.UpdateEntity(ctx, created.EntityID, updateReq)
	if err != nil {
		t.Fatalf("Failed to update entity: %v", err)
	}

	if updated.Name != "updated-entity-name" {
		t.Errorf("Expected name 'updated-entity-name', got %s", updated.Name)
	}
	if updated.Version != 2 {
		t.Errorf("Expected version 2, got %d", updated.Version)
	}
	if updated.ModifiedBy != "update-user" {
		t.Errorf("Expected modified by 'update-user', got %s", updated.ModifiedBy)
	}
}

func TestEntityManager_DeleteEntity(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create an entity
	req := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "delete-test-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	}

	created, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Delete the entity
	err = em.DeleteEntity(ctx, created.EntityID)
	if err != nil {
		t.Fatalf("Failed to delete entity: %v", err)
	}

	// Verify entity is deleted
	_, err = em.GetEntity(ctx, created.EntityID, false)
	if err == nil {
		t.Error("Expected error when getting deleted entity")
	}
}

func TestEntityManager_QueryEntities(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create multiple entities
	for i := 0; i < 5; i++ {
		req := &EntityRequest{
			Type:      EntityTypeJSON,
			Name:      fmt.Sprintf("entity-%d", i),
			Data:      json.RawMessage(fmt.Sprintf(`{"id": %d}`, i)),
			CreatedBy:  "test-user",
			Tags:      map[string]string{"group": fmt.Sprintf("group-%d", i%2)},
		}
		if _, err := em.CreateEntity(ctx, req); err != nil {
			t.Fatalf("Failed to create entity %d: %v", i, err)
		}
	}

	// Query all entities
	allEntities, err := em.QueryEntities(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to query entities: %v", err)
	}
	if len(allEntities) != 5 {
		t.Errorf("Expected 5 entities, got %d", len(allEntities))
	}

	// Query by type
	typeOpts := &EntityQueryOptions{
		Type: EntityTypeJSON,
	}
	jsonEntities, err := em.QueryEntities(ctx, typeOpts)
	if err != nil {
		t.Fatalf("Failed to query by type: %v", err)
	}
	if len(jsonEntities) != 5 {
		t.Errorf("Expected 5 JSON entities, got %d", len(jsonEntities))
	}

	// Query by tag
	tagOpts := &EntityQueryOptions{
		Tags: map[string]string{"group": "group-0"},
	}
	taggedEntities, err := em.QueryEntities(ctx, tagOpts)
	if err != nil {
		t.Fatalf("Failed to query by tag: %v", err)
	}
	if len(taggedEntities) != 3 {
		t.Errorf("Expected 3 entities with tag group-0, got %d", len(taggedEntities))
	}

	// Query with pagination
	paginatedOpts := &EntityQueryOptions{
		Limit:  2,
		Offset: 1,
	}
	paginatedEntities, err := em.QueryEntities(ctx, paginatedOpts)
	if err != nil {
		t.Fatalf("Failed to query with pagination: %v", err)
	}
	if len(paginatedEntities) != 2 {
		t.Errorf("Expected 2 paginated entities, got %d", len(paginatedEntities))
	}
}

func TestEntityManager_AddRelation(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create two entities
	entity1, err := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "parent-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity 1: %v", err)
	}

	entity2, err := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "child-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity 2: %v", err)
	}

	// Add relation
	relReq := &EntityRelationRequest{
		SourceEntity:  entity1.EntityID,
		TargetEntity:  entity2.EntityID,
		RelationType:  RelationTypeContains,
		Bidirectional: false,
		CreatedBy:     "test-user",
	}

	relation, err := em.AddRelation(ctx, relReq)
	if err != nil {
		t.Fatalf("Failed to add relation: %v", err)
	}

	if relation.RelationID == "" {
		t.Error("Relation ID should not be empty")
	}
	if relation.SourceEntity != entity1.EntityID {
		t.Errorf("Expected source %s, got %s", entity1.EntityID, relation.SourceEntity)
	}
	if relation.TargetEntity != entity2.EntityID {
		t.Errorf("Expected target %s, got %s", entity2.EntityID, relation.TargetEntity)
	}
	if relation.RelationType != RelationTypeContains {
		t.Errorf("Expected relation type %s, got %s", RelationTypeContains, relation.RelationType)
	}
}

func TestEntityManager_AddRelationBidirectional(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create two entities
	entity1, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Add bidirectional relation
	relReq := &EntityRelationRequest{
		SourceEntity:  entity1.EntityID,
		TargetEntity:  entity2.EntityID,
		RelationType:  RelationTypeRelatedTo,
		Bidirectional: true,
		CreatedBy:     "test-user",
	}

	relation, err := em.AddRelation(ctx, relReq)
	if err != nil {
		t.Fatalf("Failed to add bidirectional relation: %v", err)
	}

	if !relation.Bidirectional {
		t.Error("Expected bidirectional relation to be true")
	}
}

func TestEntityManager_AddRelationCircular(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create an entity
	entity, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "circular-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Try to add circular relation
	relReq := &EntityRelationRequest{
		SourceEntity:  entity.EntityID,
		TargetEntity:  entity.EntityID,
		RelationType:  RelationTypeContains,
		CreatedBy:     "test-user",
	}

	_, err := em.AddRelation(ctx, relReq)
	if err != ErrCircularReference {
		t.Errorf("Expected ErrCircularReference, got %v", err)
	}
}

func TestEntityManager_RemoveRelation(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create two entities and a relation
	entity1, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	relReq := &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity2.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	}

	relation, _ := em.AddRelation(ctx, relReq)

	// Remove relation
	err := em.RemoveRelation(ctx, relation.RelationID)
	if err != nil {
		t.Fatalf("Failed to remove relation: %v", err)
	}

	// Verify relation is removed
	relations, _ := em.GetRelations(ctx, entity1.EntityID, nil)
	if len(relations) != 0 {
		t.Errorf("Expected 0 relations after removal, got %d", len(relations))
	}
}

func TestEntityManager_GetRelations(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create three entities
	entity1, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity3, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-3",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Add multiple relations
	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity2.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})

	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity3.EntityID,
		RelationType: RelationTypeReferences,
		CreatedBy:    "test-user",
	})

	// Get all relations for entity1
	relations, err := em.GetRelations(ctx, entity1.EntityID, nil)
	if err != nil {
		t.Fatalf("Failed to get relations: %v", err)
	}

	if len(relations) != 2 {
		t.Errorf("Expected 2 relations, got %d", len(relations))
	}

	// Get relations by type
	typeOpts := &EntityRelationQueryOptions{
		RelationType: RelationTypeContains,
	}
	containsRelations, err := em.GetRelations(ctx, entity1.EntityID, typeOpts)
	if err != nil {
		t.Fatalf("Failed to get relations by type: %v", err)
	}

	if len(containsRelations) != 1 {
		t.Errorf("Expected 1 contains relation, got %d", len(containsRelations))
	}
}

func TestEntityManager_GetRelatedEntities(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create a hierarchy: entity1 -> entity2 -> entity3
	entity1, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity3, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-3",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Add relations
	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity2.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})

	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity2.EntityID,
		TargetEntity: entity3.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})

	// Get related entities with depth 1
	related, err := em.GetRelatedEntities(ctx, entity1.EntityID, RelationTypeContains, 1)
	if err != nil {
		t.Fatalf("Failed to get related entities: %v", err)
	}

	// Should include entity1 and entity2 (depth 1)
	if len(related) < 1 {
		t.Errorf("Expected at least 1 related entity, got %d", len(related))
	}

	// Get related entities with depth 2
	relatedDeep, err := em.GetRelatedEntities(ctx, entity1.EntityID, RelationTypeContains, 2)
	if err != nil {
		t.Fatalf("Failed to get related entities with depth: %v", err)
	}

	// Should include all three entities
	if len(relatedDeep) < 2 {
		t.Errorf("Expected at least 2 related entities with depth 2, got %d", len(relatedDeep))
	}
}

func TestEntityManager_GetEntityGraph(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create a graph: entity1 -> entity2, entity1 -> entity3
	entity1, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity3, _ := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-3",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Add relations
	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity2.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})

	em.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity3.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})

	// Get entity graph
	graph, err := em.GetEntityGraph(ctx, entity1.EntityID, 2)
	if err != nil {
		t.Fatalf("Failed to get entity graph: %v", err)
	}

	if len(graph) < 3 {
		t.Errorf("Expected at least 3 entities in graph, got %d", len(graph))
	}

	// Verify all entities are in graph
	if _, ok := graph[entity1.EntityID]; !ok {
		t.Error("Entity1 should be in graph")
	}
	if _, ok := graph[entity2.EntityID]; !ok {
		t.Error("Entity2 should be in graph")
	}
	if _, ok := graph[entity3.EntityID]; !ok {
		t.Error("Entity3 should be in graph")
	}
}

func TestEntityManager_SearchEntitiesByTag(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create entities with different tags
	em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "tagged-entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
		Tags:      map[string]string{"category": "important", "priority": "high"},
	})

	em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "tagged-entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
		Tags:      map[string]string{"category": "important", "priority": "low"},
	})

	em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "untagged-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Search by tag
	entities, err := em.SearchEntitiesByTag(ctx, "category", "important")
	if err != nil {
		t.Fatalf("Failed to search by tag: %v", err)
	}

	if len(entities) != 2 {
		t.Errorf("Expected 2 entities with category=important, got %d", len(entities))
	}

	// Search by specific tag value
	entities, err = em.SearchEntitiesByTag(ctx, "priority", "high")
	if err != nil {
		t.Fatalf("Failed to search by priority tag: %v", err)
	}

	if len(entities) != 1 {
		t.Errorf("Expected 1 entity with priority=high, got %d", len(entities))
	}
}

func TestEntityManager_GetEntitySecret(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Store a secret
	secretKey := []byte("secret:test-secret")
	secretValue := []byte("my-secret-value")
	if err := db.Put(secretKey, secretValue); err != nil {
		t.Fatalf("Failed to store secret: %v", err)
	}

	// Create entity referencing the secret
	entity, err := em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeSecret,
		Name:      "secret-entity",
		SecretRef: "test-secret",
		CreatedBy: "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Get secret through entity
	retrievedSecret, err := em.GetEntitySecret(ctx, entity.EntityID)
	if err != nil {
		t.Fatalf("Failed to get entity secret: %v", err)
	}

	if string(retrievedSecret) != "my-secret-value" {
		t.Errorf("Expected secret 'my-secret-value', got %s", string(retrievedSecret))
	}
}

func TestEntityManager_GetEntityObject(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Store an object
	objectData := []byte("test object content")
	meta, err := db.StoreObject("test/object.txt", "text/plain", "test-user", objectData, &ObjectOptions{
		Encrypt: false,
	})
	if err != nil {
		t.Fatalf("Failed to store object: %v", err)
	}

	// Create entity referencing the object
	entity, err := em.CreateEntity(ctx, &EntityRequest{
		Type:       EntityTypeObject,
		Name:       "object-entity",
		ObjectPath: meta.Path,
		CreatedBy:  "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Get object through entity
	retrievedData, retrievedMeta, err := em.GetEntityObject(ctx, entity.EntityID, "test-user")
	if err != nil {
		t.Fatalf("Failed to get entity object: %v", err)
	}

	if string(retrievedData) != "test object content" {
		t.Errorf("Expected object data 'test object content', got %s", string(retrievedData))
	}
	if retrievedMeta.Path != meta.Path {
		t.Errorf("Expected path %s, got %s", meta.Path, retrievedMeta.Path)
	}
}

func TestEntityManager_GetEntityEnvelope(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create an envelope
	envReq := &EnvelopeRequest{
		Label:     "test-envelope",
		Type:      EnvelopeTypeCourtEvidence,
		CreatedBy: "test-user",
		Payload: EnvelopePayload{
			Kind: "kv",
			Key:  "test-key",
			Value: json.RawMessage(`{"test": "value"}`),
		},
	}

	envelope, err := db.CreateEnvelope(ctx, envReq)
	if err != nil {
		t.Fatalf("Failed to create envelope: %v", err)
	}

	// Create entity referencing the envelope
	entity, err := em.CreateEntity(ctx, &EntityRequest{
		Type:       EntityTypeJSON,
		Name:       "envelope-entity",
		EnvelopeID: envelope.EnvelopeID,
		CreatedBy:  "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Get envelope through entity
	retrievedEnvelope, err := em.GetEntityEnvelope(ctx, entity.EntityID)
	if err != nil {
		t.Fatalf("Failed to get entity envelope: %v", err)
	}

	if retrievedEnvelope.EnvelopeID != envelope.EnvelopeID {
		t.Errorf("Expected envelope ID %s, got %s", envelope.EnvelopeID, retrievedEnvelope.EnvelopeID)
	}
}

func TestEntityManager_EntityEncryption(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create encrypted entity
	jsonData := json.RawMessage(`{"sensitive": "data"}`)
	req := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "encrypted-entity",
		Data:      jsonData,
		Encrypt:   true,
		CreatedBy: "test-user",
	}

	entity, err := em.CreateEntity(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create encrypted entity: %v", err)
	}

	if !entity.Encrypted {
		t.Error("Entity should be marked as encrypted")
	}

	// Retrieve and verify data is decrypted
	result, err := em.GetEntity(ctx, entity.EntityID, false)
	if err != nil {
		t.Fatalf("Failed to get encrypted entity: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(result.Entity.Data, &data); err != nil {
		t.Fatalf("Failed to unmarshal entity data: %v", err)
	}

	if data["sensitive"] != "data" {
		t.Errorf("Expected sensitive data 'data', got %v", data["sensitive"])
	}
}

func TestEntityManager_QueryEntitiesWithSorting(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create entities with different names
	names := []string{"zebra", "apple", "banana"}
	for _, name := range names {
		req := &EntityRequest{
			Type:      EntityTypeJSON,
			Name:      name,
			Data:      json.RawMessage(`{}`),
			CreatedBy: "test-user",
		}
		if _, err := em.CreateEntity(ctx, req); err != nil {
			t.Fatalf("Failed to create entity %s: %v", name, err)
		}
	}

	// Query with ascending sort
	opts := &EntityQueryOptions{
		SortBy:    "name",
		SortOrder: "asc",
	}
	entities, err := em.QueryEntities(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to query with sorting: %v", err)
	}

	if len(entities) != 3 {
		t.Errorf("Expected 3 entities, got %d", len(entities))
	}

	if entities[0].Name != "apple" {
		t.Errorf("Expected first entity to be 'apple', got %s", entities[0].Name)
	}

	// Query with descending sort
	opts.SortOrder = "desc"
	entities, err = em.QueryEntities(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to query with descending sort: %v", err)
	}

	if entities[0].Name != "zebra" {
		t.Errorf("Expected first entity to be 'zebra', got %s", entities[0].Name)
	}
}

func TestEntityManager_QueryEntitiesWithTimeFilters(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	em := db.EntityManager()
	ctx := context.Background()

	// Create entities at different times
	now := time.Now().UTC()
	oldTime := now.Add(-24 * time.Hour)

	// Create old entity
	oldEntityReq := &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "old-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	}
	oldEntity, err := em.CreateEntity(ctx, oldEntityReq)
	if err != nil {
		t.Fatalf("Failed to create old entity: %v", err)
	}
	// Manually set creation time for testing
	oldEntity.CreatedAt = oldTime
	em.saveEntity(oldEntity)

	// Create new entity
	em.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "new-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Query entities created after old time
	opts := &EntityQueryOptions{
		CreatedAfter: &oldTime,
	}
	entities, err := em.QueryEntities(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to query with time filter: %v", err)
	}

	// Should include new-entity but not old-entity
	foundNew := false
	for _, entity := range entities {
		if entity.Name == "new-entity" {
			foundNew = true
		}
	}

	if !foundNew {
		t.Error("Expected to find new-entity in results")
	}
}

// Test DB convenience methods
func TestDB_EntityMethods(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test CreateEntity
	entity, err := db.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "test-entity",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to create entity via DB method: %v", err)
	}

	// Test GetEntity
	result, err := db.GetEntity(ctx, entity.EntityID, false)
	if err != nil {
		t.Fatalf("Failed to get entity via DB method: %v", err)
	}
	if result.Entity.EntityID != entity.EntityID {
		t.Error("Entity ID mismatch")
	}

	// Test QueryEntities
	entities, err := db.QueryEntities(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to query entities via DB method: %v", err)
	}
	if len(entities) != 1 {
		t.Errorf("Expected 1 entity, got %d", len(entities))
	}

	// Test DeleteEntity
	err = db.DeleteEntity(ctx, entity.EntityID)
	if err != nil {
		t.Fatalf("Failed to delete entity via DB method: %v", err)
	}
}

func TestDB_RelationMethods(t *testing.T) {
	db, cleanup := setupEntityTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create two entities
	entity1, _ := db.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-1",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	entity2, _ := db.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "entity-2",
		Data:      json.RawMessage(`{}`),
		CreatedBy: "test-user",
	})

	// Test AddRelation
	relation, err := db.AddRelation(ctx, &EntityRelationRequest{
		SourceEntity: entity1.EntityID,
		TargetEntity: entity2.EntityID,
		RelationType: RelationTypeContains,
		CreatedBy:    "test-user",
	})
	if err != nil {
		t.Fatalf("Failed to add relation via DB method: %v", err)
	}

	// Test GetRelations
	relations, err := db.GetRelations(ctx, entity1.EntityID, nil)
	if err != nil {
		t.Fatalf("Failed to get relations via DB method: %v", err)
	}
	if len(relations) != 1 {
		t.Errorf("Expected 1 relation, got %d", len(relations))
	}

	// Test RemoveRelation
	err = db.RemoveRelation(ctx, relation.RelationID)
	if err != nil {
		t.Fatalf("Failed to remove relation via DB method: %v", err)
	}
}

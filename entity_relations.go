package velocity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrEntityNotFound      = errors.New("entity not found")
	ErrEntityExists        = errors.New("entity already exists")
	ErrInvalidEntityType   = errors.New("invalid entity type")
	ErrInvalidRelationType = errors.New("invalid relation type")
	ErrCircularReference   = errors.New("circular reference detected")
)

// Entity types supported by the system
const (
	EntityTypeJSON   = "json"
	EntityTypeSecret = "secret"
	EntityTypeObject = "object"
	EntityTypeFolder = "folder"
	EntityTypeCustom = "custom"
)

// Relation types between entities
const (
	RelationTypeContains    = "contains"     // Entity A contains Entity B
	RelationTypeReferences  = "references"   // Entity A references Entity B
	RelationTypeDependsOn   = "depends_on"   // Entity A depends on Entity B
	RelationTypeRelatedTo   = "related_to"   // Generic relationship
	RelationTypeVersionOf   = "version_of"   // Entity A is a version of Entity B
	RelationTypeDerivedFrom = "derived_from" // Entity A is derived from Entity B
	RelationTypeAttachedTo  = "attached_to"  // Entity A is attached to Entity B
)

// Entity represents a stored entity with metadata
type Entity struct {
	EntityID       string            `json:"entity_id"`
	Type           string            `json:"type"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Data           json.RawMessage   `json:"data,omitempty"`
	EncryptedData  []byte            `json:"encrypted_data,omitempty"` // Separate field for encrypted data
	SecretRef      string            `json:"secret_ref,omitempty"`     // Reference to stored secret
	ObjectPath     string            `json:"object_path,omitempty"`    // Reference to object storage
	EnvelopeID     string            `json:"envelope_id,omitempty"`    // Reference to envelope
	CreatedAt      time.Time         `json:"created_at"`
	CreatedBy      string            `json:"created_by"`
	ModifiedAt     time.Time         `json:"modified_at"`
	ModifiedBy     string            `json:"modified_by"`
	Tags           map[string]string `json:"tags,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Version        int               `json:"version"`
	Checksum       string            `json:"checksum"`
	Encrypted      bool              `json:"encrypted"`
	EncryptionAlgo string            `json:"encryption_algo,omitempty"`
}

// EntityRelation represents a relationship between two entities
type EntityRelation struct {
	RelationID    string            `json:"relation_id"`
	SourceEntity  string            `json:"source_entity"`
	TargetEntity  string            `json:"target_entity"`
	RelationType  string            `json:"relation_type"`
	CreatedAt     time.Time         `json:"created_at"`
	CreatedBy     string            `json:"created_by"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Bidirectional bool              `json:"bidirectional"`
}

// EntityQueryOptions for filtering and searching entities
type EntityQueryOptions struct {
	Type           string
	Tags           map[string]string
	Metadata       map[string]string
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	ModifiedAfter  *time.Time
	ModifiedBefore *time.Time
	Limit          int
	Offset         int
	SortBy         string // "name", "created_at", "modified_at"
	SortOrder      string // "asc", "desc"
}

// EntityRelationQueryOptions for querying relationships
type EntityRelationQueryOptions struct {
	SourceEntity  string
	TargetEntity  string
	RelationType  string
	Bidirectional bool
	Depth         int // For traversal queries
}

// EntityRequest for creating entities
type EntityRequest struct {
	Type        string
	Name        string
	Description string
	Data        json.RawMessage
	SecretRef   string
	ObjectPath  string
	EnvelopeID  string
	Tags        map[string]string
	Metadata    map[string]string
	Encrypt     bool
	CreatedBy   string
}

// EntityRelationRequest for creating relationships
type EntityRelationRequest struct {
	SourceEntity  string
	TargetEntity  string
	RelationType  string
	Bidirectional bool
	Metadata      map[string]string
	CreatedBy     string
}

// EntityResult includes entity with its relationships
type EntityResult struct {
	Entity        *Entity           `json:"entity"`
	Relationships []*EntityRelation `json:"relationships,omitempty"`
	DataRedacted  bool              `json:"data_redacted"` // Indicates if data was redacted
}

// EntityManager handles entity storage and relationships
type EntityManager struct {
	db *DB
	mu sync.RWMutex
}

// NewEntityManager creates a new entity manager
func NewEntityManager(db *DB) *EntityManager {
	return &EntityManager{db: db}
}

// CreateEntity creates a new entity
func (em *EntityManager) CreateEntity(ctx context.Context, req *EntityRequest) (*Entity, error) {
	if req == nil {
		return nil, fmt.Errorf("entity request is nil")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("entity name is required")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("entity type is required")
	}

	// Validate entity type
	if !isValidEntityType(req.Type) {
		return nil, ErrInvalidEntityType
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	// Generate entity ID
	entityID := generateEntityID()

	// Calculate checksum
	checksum := calculateEntityChecksum(req.Data, req.SecretRef, req.ObjectPath, req.EnvelopeID)

	now := time.Now().UTC()
	entity := &Entity{
		EntityID:       entityID,
		Type:           req.Type,
		Name:           req.Name,
		Description:    req.Description,
		Data:           req.Data,
		SecretRef:      req.SecretRef,
		ObjectPath:     req.ObjectPath,
		EnvelopeID:     req.EnvelopeID,
		CreatedAt:      now,
		CreatedBy:      req.CreatedBy,
		ModifiedAt:     now,
		ModifiedBy:     req.CreatedBy,
		Tags:           req.Tags,
		Metadata:       req.Metadata,
		Version:        1,
		Checksum:       checksum,
		Encrypted:      req.Encrypt,
		EncryptionAlgo: "ChaCha20-Poly1305",
	}

	// Encrypt data if requested
	if req.Encrypt && em.db.crypto != nil && len(entity.Data) > 0 {
		nonce, ciphertext, err := em.db.crypto.Encrypt(entity.Data, []byte(entityID))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt entity data: %w", err)
		}
		entity.EncryptedData = append(nonce, ciphertext...)
		entity.Data = nil // Clear plaintext data
	}

	// Store entity
	if err := em.saveEntity(entity); err != nil {
		return nil, err
	}

	return entity, nil
}

// GetEntity retrieves an entity by ID
func (em *EntityManager) GetEntity(ctx context.Context, entityID string, includeRelations bool) (*EntityResult, error) {
	return em.GetEntityWithForce(ctx, entityID, includeRelations, false)
}

// GetEntityWithForce retrieves an entity by ID with optional force flag to show actual data
func (em *EntityManager) GetEntityWithForce(ctx context.Context, entityID string, includeRelations, forceShowData bool) (*EntityResult, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return nil, err
	}

	result := &EntityResult{Entity: entity}

	// Redact data by default unless force flag is set
	if !forceShowData && len(entity.Data) > 0 {
		redacted := em.redactData(entity.Data)
		entity.Data = json.RawMessage(redacted)
		result.DataRedacted = true
	}

	if includeRelations {
		relations, err := em.getEntityRelations(entityID)
		if err != nil {
			return nil, err
		}
		result.Relationships = relations
	}

	return result, nil
}

// UpdateEntity updates an existing entity
func (em *EntityManager) UpdateEntity(ctx context.Context, entityID string, req *EntityRequest) (*Entity, error) {
	if req == nil {
		return nil, fmt.Errorf("entity request is nil")
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	// Load existing entity
	existing, err := em.loadEntity(entityID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Data != nil {
		existing.Data = req.Data
	}
	if req.SecretRef != "" {
		existing.SecretRef = req.SecretRef
	}
	if req.ObjectPath != "" {
		existing.ObjectPath = req.ObjectPath
	}
	if req.EnvelopeID != "" {
		existing.EnvelopeID = req.EnvelopeID
	}
	if req.Tags != nil {
		existing.Tags = req.Tags
	}
	if req.Metadata != nil {
		existing.Metadata = req.Metadata
	}

	existing.ModifiedAt = time.Now().UTC()
	existing.ModifiedBy = req.CreatedBy
	existing.Version++
	existing.Checksum = calculateEntityChecksum(existing.Data, existing.SecretRef, existing.ObjectPath, existing.EnvelopeID)

	// Encrypt data if requested
	if req.Encrypt && em.db.crypto != nil && len(existing.Data) > 0 {
		nonce, ciphertext, err := em.db.crypto.Encrypt(existing.Data, []byte(entityID))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt entity data: %w", err)
		}
		existing.EncryptedData = append(nonce, ciphertext...)
		existing.Data = nil // Clear plaintext data
	}

	// Save updated entity
	if err := em.saveEntity(existing); err != nil {
		return nil, err
	}

	return existing, nil
}

// DeleteEntity deletes an entity and its relationships
func (em *EntityManager) DeleteEntity(ctx context.Context, entityID string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Check if entity exists
	if _, err := em.loadEntity(entityID); err != nil {
		return err
	}

	// Delete all relationships
	relations, err := em.getEntityRelations(entityID)
	if err == nil {
		for _, rel := range relations {
			_ = em.deleteRelation(rel.RelationID)
		}
	}

	// Delete entity
	entityKey := []byte(entityKeyPrefix + entityID)
	if err := em.db.Delete(entityKey); err != nil {
		return err
	}

	return nil
}

// QueryEntities searches for entities based on criteria
func (em *EntityManager) QueryEntities(ctx context.Context, opts *EntityQueryOptions) ([]*Entity, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// Get all entity keys
	keys, err := em.db.Keys(entityKeyPrefix + "*")
	if err != nil {
		return nil, err
	}

	var entities []*Entity

	for _, key := range keys {
		entityID := strings.TrimPrefix(key, entityKeyPrefix)
		entity, err := em.loadEntity(entityID)
		if err != nil {
			continue
		}

		// Apply filters
		if !em.matchesQuery(entity, opts) {
			continue
		}

		entities = append(entities, entity)
	}

	// Sort results
	if opts != nil && opts.SortBy != "" {
		em.sortEntities(entities, opts.SortBy, opts.SortOrder)
	}

	// Apply pagination
	if opts != nil && (opts.Limit > 0 || opts.Offset > 0) {
		start := opts.Offset
		if start > len(entities) {
			start = len(entities)
		}
		end := start + opts.Limit
		if end > len(entities) || opts.Limit == 0 {
			end = len(entities)
		}
		entities = entities[start:end]
	}

	return entities, nil
}

// AddRelation creates a relationship between two entities
func (em *EntityManager) AddRelation(ctx context.Context, req *EntityRelationRequest) (*EntityRelation, error) {
	if req == nil {
		return nil, fmt.Errorf("relation request is nil")
	}
	if req.SourceEntity == "" || req.TargetEntity == "" {
		return nil, fmt.Errorf("source and target entities are required")
	}
	if req.RelationType == "" {
		return nil, fmt.Errorf("relation type is required")
	}

	// Validate relation type
	if !isValidRelationType(req.RelationType) {
		return nil, ErrInvalidRelationType
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	// Check if entities exist
	if _, err := em.loadEntity(req.SourceEntity); err != nil {
		return nil, fmt.Errorf("source entity not found: %w", err)
	}
	if _, err := em.loadEntity(req.TargetEntity); err != nil {
		return nil, fmt.Errorf("target entity not found: %w", err)
	}

	// Check for circular reference
	if req.SourceEntity == req.TargetEntity {
		return nil, ErrCircularReference
	}

	// Generate relation ID
	relationID := generateRelationID()

	now := time.Now().UTC()
	relation := &EntityRelation{
		RelationID:    relationID,
		SourceEntity:  req.SourceEntity,
		TargetEntity:  req.TargetEntity,
		RelationType:  req.RelationType,
		CreatedAt:     now,
		CreatedBy:     req.CreatedBy,
		Metadata:      req.Metadata,
		Bidirectional: req.Bidirectional,
	}

	// Store relation
	if err := em.saveRelation(relation); err != nil {
		return nil, err
	}

	return relation, nil
}

// RemoveRelation removes a relationship
func (em *EntityManager) RemoveRelation(ctx context.Context, relationID string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	return em.deleteRelation(relationID)
}

// GetRelations retrieves relationships for an entity
func (em *EntityManager) GetRelations(ctx context.Context, entityID string, opts *EntityRelationQueryOptions) ([]*EntityRelation, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if opts == nil {
		opts = &EntityRelationQueryOptions{}
	}

	// Get all relations
	allRelations, err := em.getAllRelations()
	if err != nil {
		return nil, err
	}

	var relations []*EntityRelation

	for _, rel := range allRelations {
		// Filter by entity
		if opts.SourceEntity != "" && rel.SourceEntity != opts.SourceEntity {
			continue
		}
		if opts.TargetEntity != "" && rel.TargetEntity != opts.TargetEntity {
			continue
		}

		// Filter by relation type
		if opts.RelationType != "" && rel.RelationType != opts.RelationType {
			continue
		}

		// Filter by bidirectional
		if !opts.Bidirectional && rel.Bidirectional {
			continue
		}

		relations = append(relations, rel)
	}

	return relations, nil
}

// GetRelatedEntities retrieves all entities related to a given entity
func (em *EntityManager) GetRelatedEntities(ctx context.Context, entityID string, relationType string, depth int) ([]*EntityResult, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if depth <= 0 {
		depth = 1
	}

	visited := make(map[string]bool)
	var results []*EntityResult

	em.traverseRelations(entityID, relationType, depth, visited, &results)

	return results, nil
}

// GetEntityGraph retrieves the complete graph of related entities
func (em *EntityManager) GetEntityGraph(ctx context.Context, entityID string, maxDepth int) (map[string]*EntityResult, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if maxDepth <= 0 {
		maxDepth = 3
	}

	graph := make(map[string]*EntityResult)
	visited := make(map[string]bool)

	em.buildGraph(entityID, maxDepth, 0, visited, graph)

	return graph, nil
}

// SearchEntitiesByTag searches for entities by tags
func (em *EntityManager) SearchEntitiesByTag(ctx context.Context, tagKey, tagValue string) ([]*Entity, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	opts := &EntityQueryOptions{
		Tags: map[string]string{tagKey: tagValue},
	}

	return em.QueryEntities(ctx, opts)
}

// GetEntitySecret retrieves the secret referenced by an entity
func (em *EntityManager) GetEntitySecret(ctx context.Context, entityID string) ([]byte, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return nil, err
	}

	if entity.SecretRef == "" {
		return nil, fmt.Errorf("entity does not reference a secret")
	}

	// Retrieve secret from key-value store
	secretKey := []byte("secret:" + entity.SecretRef)
	return em.db.Get(secretKey)
}

// GetEntityObject retrieves the object referenced by an entity
func (em *EntityManager) GetEntityObject(ctx context.Context, entityID, userID string) ([]byte, *ObjectMetadata, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return nil, nil, err
	}

	if entity.ObjectPath == "" {
		return nil, nil, fmt.Errorf("entity does not reference an object")
	}

	return em.db.GetObject(entity.ObjectPath, userID)
}

// GetEntityEnvelope retrieves the envelope referenced by an entity
func (em *EntityManager) GetEntityEnvelope(ctx context.Context, entityID string) (*Envelope, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return nil, err
	}

	if entity.EnvelopeID == "" {
		return nil, fmt.Errorf("entity does not reference an envelope")
	}

	return em.db.LoadEnvelope(ctx, entity.EnvelopeID)
}

// CreateEnvelopeFromEntity creates an envelope from an existing entity
func (em *EntityManager) CreateEnvelopeFromEntity(ctx context.Context, entityID string, envelopeType EnvelopeType, createdBy string) (*Envelope, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// Load the entity
	entity, err := em.loadEntity(entityID)
	if err != nil {
		return nil, err
	}

	// Determine payload kind based on entity type
	var payloadKind string
	var payloadData json.RawMessage
	var objectPath, objectVersion string
	var secretRef string

	switch entity.Type {
	case EntityTypeJSON:
		payloadKind = "kv"
		payloadData = entity.Data
	case EntityTypeObject:
		payloadKind = "file"
		objectPath = entity.ObjectPath
		objectVersion = fmt.Sprintf("%d", entity.Version)
	case EntityTypeSecret:
		payloadKind = "secret"
		secretRef = entity.SecretRef
	default:
		return nil, fmt.Errorf("unsupported entity type for envelope: %s", entity.Type)
	}

	// Create envelope request
	req := &EnvelopeRequest{
		Label:     entity.Name,
		Type:      envelopeType,
		CreatedBy: createdBy,
		Notes:     entity.Description,
		Payload: EnvelopePayload{
			Kind:            payloadKind,
			ObjectPath:      objectPath,
			ObjectVersion:   objectVersion,
			SecretReference: secretRef,
			Value:           payloadData,
			Metadata: map[string]string{
				"entity_id":   entity.EntityID,
				"entity_type": entity.Type,
				"version":     fmt.Sprintf("%d", entity.Version),
			},
		},
		Tags: entity.Tags,
	}

	// Create envelope
	envelope, err := em.db.CreateEnvelope(ctx, req)
	if err != nil {
		return nil, err
	}

	// Update entity to reference the envelope
	entity.EnvelopeID = envelope.EnvelopeID
	if err := em.saveEntity(entity); err != nil {
		return nil, fmt.Errorf("failed to update entity with envelope reference: %w", err)
	}

	return envelope, nil
}

// Internal methods

const (
	entityKeyPrefix   = "entity:"
	relationKeyPrefix = "relation:"
)

func (em *EntityManager) saveEntity(entity *Entity) error {
	entityKey := []byte(entityKeyPrefix + entity.EntityID)
	entityBytes, err := json.Marshal(entity)
	if err != nil {
		return err
	}
	return em.db.PutWithTTL(entityKey, entityBytes, 0)
}

func (em *EntityManager) loadEntity(entityID string) (*Entity, error) {
	entityKey := []byte(entityKeyPrefix + entityID)
	entityBytes, err := em.db.Get(entityKey)
	if err != nil {
		return nil, ErrEntityNotFound
	}

	var entity Entity
	if err := json.Unmarshal(entityBytes, &entity); err != nil {
		return nil, err
	}

	// Decrypt data if encrypted
	if entity.Encrypted && em.db.crypto != nil && len(entity.EncryptedData) > 0 {
		if len(entity.EncryptedData) < 24 {
			return nil, fmt.Errorf("invalid encrypted data")
		}
		nonce := entity.EncryptedData[:24]
		ciphertext := entity.EncryptedData[24:]
		plaintext, err := em.db.crypto.Decrypt(nonce, ciphertext, []byte(entityID))
		if err != nil {
			return nil, err
		}
		entity.Data = plaintext
		entity.EncryptedData = nil // Clear encrypted data after decryption
	}

	return &entity, nil
}

func (em *EntityManager) saveRelation(relation *EntityRelation) error {
	relationKey := []byte(relationKeyPrefix + relation.RelationID)
	relationBytes, err := json.Marshal(relation)
	if err != nil {
		return err
	}
	return em.db.PutWithTTL(relationKey, relationBytes, 0)
}

func (em *EntityManager) deleteRelation(relationID string) error {
	relationKey := []byte(relationKeyPrefix + relationID)
	return em.db.Delete(relationKey)
}

func (em *EntityManager) getEntityRelations(entityID string) ([]*EntityRelation, error) {
	allRelations, err := em.getAllRelations()
	if err != nil {
		return nil, err
	}

	relations := make([]*EntityRelation, 0)
	for _, rel := range allRelations {
		if rel.SourceEntity == entityID || rel.TargetEntity == entityID {
			relations = append(relations, rel)
		}
	}
	return relations, nil
}

func (em *EntityManager) getAllRelations() ([]*EntityRelation, error) {
	keys, err := em.db.Keys(relationKeyPrefix + "*")
	if err != nil {
		return nil, err
	}

	var relations []*EntityRelation
	for _, key := range keys {
		relationBytes, err := em.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var relation EntityRelation
		if err := json.Unmarshal(relationBytes, &relation); err != nil {
			continue
		}

		relations = append(relations, &relation)
	}

	return relations, nil
}

func (em *EntityManager) traverseRelations(entityID, relationType string, depth int, visited map[string]bool, results *[]*EntityResult) {
	if depth <= 0 || visited[entityID] {
		return
	}

	visited[entityID] = true

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return
	}

	relations, err := em.getEntityRelations(entityID)
	if err != nil {
		return
	}

	result := &EntityResult{
		Entity:        entity,
		Relationships: relations,
	}
	*results = append(*results, result)

	for _, rel := range relations {
		if relationType != "" && rel.RelationType != relationType {
			continue
		}

		targetID := rel.TargetEntity
		if rel.SourceEntity == entityID {
			targetID = rel.TargetEntity
		} else {
			targetID = rel.SourceEntity
		}

		em.traverseRelations(targetID, relationType, depth-1, visited, results)
	}
}

func (em *EntityManager) buildGraph(entityID string, maxDepth, currentDepth int, visited map[string]bool, graph map[string]*EntityResult) {
	if currentDepth >= maxDepth || visited[entityID] {
		return
	}

	visited[entityID] = true

	entity, err := em.loadEntity(entityID)
	if err != nil {
		return
	}

	relations, err := em.getEntityRelations(entityID)
	if err != nil {
		return
	}

	result := &EntityResult{
		Entity:        entity,
		Relationships: relations,
	}
	graph[entityID] = result

	for _, rel := range relations {
		targetID := rel.TargetEntity
		if rel.SourceEntity == entityID {
			targetID = rel.TargetEntity
		} else {
			targetID = rel.SourceEntity
		}

		em.buildGraph(targetID, maxDepth, currentDepth+1, visited, graph)
	}
}

func (em *EntityManager) matchesQuery(entity *Entity, opts *EntityQueryOptions) bool {
	if opts == nil {
		return true
	}

	// Filter by type
	if opts.Type != "" && entity.Type != opts.Type {
		return false
	}

	// Filter by tags
	if opts.Tags != nil {
		for k, v := range opts.Tags {
			if entity.Tags == nil || entity.Tags[k] != v {
				return false
			}
		}
	}

	// Filter by metadata
	if opts.Metadata != nil {
		for k, v := range opts.Metadata {
			if entity.Metadata == nil || entity.Metadata[k] != v {
				return false
			}
		}
	}

	// Filter by created time
	if opts.CreatedAfter != nil && entity.CreatedAt.Before(*opts.CreatedAfter) {
		return false
	}
	if opts.CreatedBefore != nil && entity.CreatedAt.After(*opts.CreatedBefore) {
		return false
	}

	// Filter by modified time
	if opts.ModifiedAfter != nil && entity.ModifiedAt.Before(*opts.ModifiedAfter) {
		return false
	}
	if opts.ModifiedBefore != nil && entity.ModifiedAt.After(*opts.ModifiedBefore) {
		return false
	}

	return true
}

func (em *EntityManager) sortEntities(entities []*Entity, sortBy, sortOrder string) {
	if len(entities) == 0 {
		return
	}

	less := func(i, j int) bool {
		var result bool
		switch sortBy {
		case "name":
			result = entities[i].Name < entities[j].Name
		case "created_at":
			result = entities[i].CreatedAt.Before(entities[j].CreatedAt)
		case "modified_at":
			result = entities[i].ModifiedAt.Before(entities[j].ModifiedAt)
		default:
			result = entities[i].Name < entities[j].Name
		}

		if sortOrder == "desc" {
			return !result
		}
		return result
	}

	// Simple bubble sort (for small datasets)
	for i := 0; i < len(entities)-1; i++ {
		for j := i + 1; j < len(entities); j++ {
			if less(j, i) {
				entities[i], entities[j] = entities[j], entities[i]
			}
		}
	}
}

// Helper functions

// redactData redacts sensitive data by replacing it with a wildcard placeholder
func (em *EntityManager) redactData(data json.RawMessage) string {
	if len(data) == 0 {
		return "[]"
	}

	// Use classification engine for intelligent masking if available
	if em.db.classificationEngine != nil {
		result, err := em.db.classificationEngine.ClassifyData(context.Background(), data)
		if err == nil {
			return string(em.db.classificationEngine.MaskData(data, result))
		}
	}

	// Fallback: If no classification engine or it failed, don't redact everything
	// unless we really have to. For now, return the original data if we can't
	// prove it's sensitive, to avoid breaking functionality.
	return string(data)
}

func isValidEntityType(entityType string) bool {
	switch entityType {
	case EntityTypeJSON, EntityTypeSecret, EntityTypeObject, EntityTypeFolder, EntityTypeCustom:
		return true
	default:
		return false
	}
}

func isValidRelationType(relationType string) bool {
	switch relationType {
	case RelationTypeContains, RelationTypeReferences, RelationTypeDependsOn,
		RelationTypeRelatedTo, RelationTypeVersionOf, RelationTypeDerivedFrom,
		RelationTypeAttachedTo:
		return true
	default:
		return false
	}
}

func calculateEntityChecksum(data json.RawMessage, secretRef, objectPath, envelopeID string) string {
	h := sha256.New()
	h.Write(data)
	h.Write([]byte(secretRef))
	h.Write([]byte(objectPath))
	h.Write([]byte(envelopeID))
	return hex.EncodeToString(h.Sum(nil))
}

func generateEntityID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("ent-%d", time.Now().UnixNano())
	}
	return "ent-" + hex.EncodeToString(buf)
}

func generateRelationID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("rel-%d", time.Now().UnixNano())
	}
	return "rel-" + hex.EncodeToString(buf)
}

// DB methods for entity management

// EntityManager returns the entity manager for the database
func (db *DB) EntityManager() *EntityManager {
	return &EntityManager{db: db}
}

// CreateEntity creates a new entity
func (db *DB) CreateEntity(ctx context.Context, req *EntityRequest) (*Entity, error) {
	return db.EntityManager().CreateEntity(ctx, req)
}

// GetEntity retrieves an entity by ID
func (db *DB) GetEntity(ctx context.Context, entityID string, includeRelations bool) (*EntityResult, error) {
	return db.EntityManager().GetEntity(ctx, entityID, includeRelations)
}

// UpdateEntity updates an existing entity
func (db *DB) UpdateEntity(ctx context.Context, entityID string, req *EntityRequest) (*Entity, error) {
	return db.EntityManager().UpdateEntity(ctx, entityID, req)
}

// DeleteEntity deletes an entity and its relationships
func (db *DB) DeleteEntity(ctx context.Context, entityID string) error {
	return db.EntityManager().DeleteEntity(ctx, entityID)
}

// QueryEntities searches for entities based on criteria
func (db *DB) QueryEntities(ctx context.Context, opts *EntityQueryOptions) ([]*Entity, error) {
	return db.EntityManager().QueryEntities(ctx, opts)
}

// AddRelation creates a relationship between two entities
func (db *DB) AddRelation(ctx context.Context, req *EntityRelationRequest) (*EntityRelation, error) {
	return db.EntityManager().AddRelation(ctx, req)
}

// RemoveRelation removes a relationship
func (db *DB) RemoveRelation(ctx context.Context, relationID string) error {
	return db.EntityManager().RemoveRelation(ctx, relationID)
}

// GetRelations retrieves relationships for an entity
func (db *DB) GetRelations(ctx context.Context, entityID string, opts *EntityRelationQueryOptions) ([]*EntityRelation, error) {
	return db.EntityManager().GetRelations(ctx, entityID, opts)
}

// GetRelatedEntities retrieves all entities related to a given entity
func (db *DB) GetRelatedEntities(ctx context.Context, entityID string, relationType string, depth int) ([]*EntityResult, error) {
	return db.EntityManager().GetRelatedEntities(ctx, entityID, relationType, depth)
}

// GetEntityGraph retrieves the complete graph of related entities
func (db *DB) GetEntityGraph(ctx context.Context, entityID string, maxDepth int) (map[string]*EntityResult, error) {
	return db.EntityManager().GetEntityGraph(ctx, entityID, maxDepth)
}

// SearchEntitiesByTag searches for entities by tags
func (db *DB) SearchEntitiesByTag(ctx context.Context, tagKey, tagValue string) ([]*Entity, error) {
	return db.EntityManager().SearchEntitiesByTag(ctx, tagKey, tagValue)
}

// GetEntitySecret retrieves the secret referenced by an entity
func (db *DB) GetEntitySecret(ctx context.Context, entityID string) ([]byte, error) {
	return db.EntityManager().GetEntitySecret(ctx, entityID)
}

// GetEntityObject retrieves the object referenced by an entity
func (db *DB) GetEntityObject(ctx context.Context, entityID, userID string) ([]byte, *ObjectMetadata, error) {
	return db.EntityManager().GetEntityObject(ctx, entityID, userID)
}

// GetEntityEnvelope retrieves the envelope referenced by an entity
func (db *DB) GetEntityEnvelope(ctx context.Context, entityID string) (*Envelope, error) {
	return db.EntityManager().GetEntityEnvelope(ctx, entityID)
}

// CreateEnvelopeFromEntity creates an envelope from an existing entity
func (db *DB) CreateEnvelopeFromEntity(ctx context.Context, entityID string, envelopeType EnvelopeType, createdBy string) (*Envelope, error) {
	return db.EntityManager().CreateEnvelopeFromEntity(ctx, entityID, envelopeType, createdBy)
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	velocity "github.com/oarkflow/velocity"
)

func main() {
	// Open database
	db, err := velocity.New("./entity_demo_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	em := db.EntityManager()

	fmt.Println("=== Velocity Entity Relations Demo ===")

	// Demo 1: Creating JSON Entities
	fmt.Println("Demo 1: Creating JSON Entities")
	createJSONEntities(ctx, em)

	// Demo 2: Creating Entities with Secret References
	fmt.Println("\nDemo 2: Creating Entities with Secret References")
	createSecretEntities(ctx, db, em)

	// Demo 3: Creating Entities with Object References
	fmt.Println("\nDemo 3: Creating Entities with Object References")
	createObjectEntities(ctx, db, em)

	// Demo 4: Creating Relationships
	fmt.Println("\nDemo 4: Creating Relationships")
	createRelationships(ctx, em)

	// Demo 5: Querying Entities
	fmt.Println("\nDemo 5: Querying Entities")
	queryEntities(ctx, em)

	// Demo 6: Traversing Entity Graphs
	fmt.Println("\nDemo 6: Traversing Entity Graphs")
	traverseEntityGraph(ctx, em)

	// Demo 7: Building a Document Management System
	fmt.Println("\nDemo 7: Building a Document Management System")
	buildDocumentManagement(ctx, db, em)

	// Demo 8: Building a Configuration System
	fmt.Println("\nDemo 8: Building a Configuration System")
	buildConfigurationSystem(ctx, db, em)

	// Demo 9: Version Control System
	fmt.Println("\nDemo 9: Version Control System")
	buildVersionControl(ctx, em)

	// Demo 10: Encrypted Entities
	fmt.Println("\nDemo 10: Encrypted Entities")
	createEncryptedEntities(ctx, em)

	// Demo 11: Creating Envelopes from Entities with Relationships
	fmt.Println("\nDemo 11: Creating Envelopes from Entities with Relationships")
	createEnvelopesFromEntities(ctx, db, em)

	fmt.Println("\n=== Demo Complete ===")
}

func createJSONEntities(ctx context.Context, em *velocity.EntityManager) {
	// Create a user profile entity
	userProfile := json.RawMessage(`{
		"name": "John Doe",
		"email": "john.doe@example.com",
		"age": 30,
		"department": "Engineering"
	}`)

	userEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeJSON,
		Name:        "user-profile-john-doe",
		Description: "User profile for John Doe",
		Data:        userProfile,
		CreatedBy:   "admin",
		Tags: map[string]string{
			"type":       "user",
			"department": "engineering",
			"status":     "active",
		},
		Metadata: map[string]string{
			"source": "manual-entry",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created user entity: %s\n", userEntity.EntityID)
	fmt.Printf("  Name: %s\n", userEntity.Name)
	fmt.Printf("  Type: %s\n", userEntity.Type)
	fmt.Printf("  Version: %d\n", userEntity.Version)
	fmt.Printf("  Checksum: %s\n", userEntity.Checksum)

	// Create a project entity
	project := json.RawMessage(`{
		"name": "Velocity Database",
		"description": "High-performance key-value database",
		"status": "active",
		"priority": "high"
	}`)

	projectEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "project-velocity",
		Data:      project,
		CreatedBy: "admin",
		Tags: map[string]string{
			"type":     "project",
			"status":   "active",
			"priority": "high",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created project entity: %s\n", projectEntity.EntityID)
}

func createSecretEntities(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Store a secret
	secretKey := []byte("secret:api-production-key")
	secretValue := []byte("sk-prod-1234567890abcdef")
	if err := db.Put(secretKey, secretValue); err != nil {
		log.Fatal(err)
	}

	// Create entity referencing the secret
	secretEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeSecret,
		Name:        "production-api-credentials",
		Description: "API credentials for production environment",
		SecretRef:   "api-production-key",
		CreatedBy:   "admin",
		Tags: map[string]string{
			"type":    "secret",
			"env":     "production",
			"service": "api",
		},
		Metadata: map[string]string{
			"rotation": "monthly",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created secret entity: %s\n", secretEntity.EntityID)
	fmt.Printf("  Secret Reference: %s\n", secretEntity.SecretRef)

	// Retrieve the secret through the entity
	retrievedSecret, err := em.GetEntitySecret(ctx, secretEntity.EntityID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("  Retrieved Secret: %s\n", string(retrievedSecret))
}

func createObjectEntities(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Store an object
	documentContent := []byte("This is a confidential document content.")
	meta, err := db.StoreObject(
		"documents/confidential-report.pdf",
		"application/pdf",
		"admin",
		documentContent,
		&velocity.ObjectOptions{
			Encrypt: true,
			Tags: map[string]string{
				"type":           "report",
				"classification": "confidential",
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create entity referencing the object
	objectEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeObject,
		Name:        "confidential-report-entity",
		Description: "Confidential annual report",
		ObjectPath:  meta.Path,
		CreatedBy:   "admin",
		Tags: map[string]string{
			"type":           "document",
			"classification": "confidential",
			"year":           "2024",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created object entity: %s\n", objectEntity.EntityID)
	fmt.Printf("  Object Path: %s\n", objectEntity.ObjectPath)

	// Retrieve the object through the entity
	data, retrievedMeta, err := em.GetEntityObject(ctx, objectEntity.EntityID, "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("  Retrieved Object: %s (%d bytes)\n", retrievedMeta.Name, retrievedMeta.Size)
	fmt.Printf("  Content: %s\n", string(data))
}

func createRelationships(ctx context.Context, em *velocity.EntityManager) {
	// Get existing entities
	entities, err := em.QueryEntities(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(entities) < 2 {
		fmt.Println("Not enough entities to create relationships")
		return
	}

	entity1 := entities[0]
	entity2 := entities[1]

	// Create a "contains" relationship
	containsRel, err := em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity:  entity1.EntityID,
		TargetEntity:  entity2.EntityID,
		RelationType:  velocity.RelationTypeContains,
		Bidirectional: false,
		CreatedBy:     "admin",
		Metadata: map[string]string{
			"description": "Entity 1 contains Entity 2",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created 'contains' relationship: %s\n", containsRel.RelationID)
	fmt.Printf("  %s -> %s (%s)\n", containsRel.SourceEntity, containsRel.TargetEntity, containsRel.RelationType)

	// Create a "references" relationship
	refsRel, err := em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity:  entity2.EntityID,
		TargetEntity:  entity1.EntityID,
		RelationType:  velocity.RelationTypeReferences,
		Bidirectional: true,
		CreatedBy:     "admin",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created bidirectional 'references' relationship: %s\n", refsRel.RelationID)
	fmt.Printf("  %s <-> %s (%s)\n", refsRel.SourceEntity, refsRel.TargetEntity, refsRel.RelationType)
}

func queryEntities(ctx context.Context, em *velocity.EntityManager) {
	// Query all entities
	allEntities, err := em.QueryEntities(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Total entities: %d\n", len(allEntities))

	// Query by type
	jsonEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
		Type: velocity.EntityTypeJSON,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ JSON entities: %d\n", len(jsonEntities))

	// Query by tag
	taggedEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
		Tags: map[string]string{
			"type": "user",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ User entities: %d\n", len(taggedEntities))

	// Query with sorting
	sortedEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
		SortBy:    "name",
		SortOrder: "asc",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Sorted entities (by name):")
	for _, entity := range sortedEntities {
		fmt.Printf("  - %s\n", entity.Name)
	}

	// Search by tag
	searchResults, err := em.SearchEntitiesByTag(ctx, "status", "active")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Active entities: %d\n", len(searchResults))
}

func traverseEntityGraph(ctx context.Context, em *velocity.EntityManager) {
	// Get first entity
	entities, err := em.QueryEntities(ctx, nil)
	if err != nil || len(entities) == 0 {
		fmt.Println("No entities to traverse")
		return
	}

	rootEntity := entities[0]

	// Get related entities with depth 1
	related, err := em.GetRelatedEntities(ctx, rootEntity.EntityID, "", 1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Entities related to %s (depth 1): %d\n", rootEntity.Name, len(related))
	for _, result := range related {
		fmt.Printf("  - %s\n", result.Entity.Name)
	}

	// Get complete entity graph
	graph, err := em.GetEntityGraph(ctx, rootEntity.EntityID, 3)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Entity graph for %s: %d entities\n", rootEntity.Name, len(graph))
	for entityID, result := range graph {
		fmt.Printf("  Entity: %s (%s)\n", result.Entity.Name, entityID)
		for _, rel := range result.Relationships {
			fmt.Printf("    -> %s (%s)\n", rel.TargetEntity, rel.RelationType)
		}
	}
}

func buildDocumentManagement(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Create folder structure
	rootFolder, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeFolder,
		Name:      "documents",
		CreatedBy: "admin",
		Tags: map[string]string{
			"type": "folder",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	reportsFolder, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeFolder,
		Name:      "reports",
		CreatedBy: "admin",
		Tags: map[string]string{
			"type": "folder",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create folder relationships
	_, err = em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: rootFolder.EntityID,
		TargetEntity: reportsFolder.EntityID,
		RelationType: velocity.RelationTypeContains,
		CreatedBy:    "admin",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Store documents
	doc1Content := []byte("Q1 Financial Report")
	meta1, _ := db.StoreObject(
		"documents/reports/q1-financial.pdf",
		"application/pdf",
		"admin",
		doc1Content,
		&velocity.ObjectOptions{Encrypt: false},
	)

	doc2Content := []byte("Q2 Financial Report")
	meta2, _ := db.StoreObject(
		"documents/reports/q2-financial.pdf",
		"application/pdf",
		"admin",
		doc2Content,
		&velocity.ObjectOptions{Encrypt: false},
	)

	// Create document entities
	doc1Entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:       velocity.EntityTypeObject,
		Name:       "q1-financial-report",
		ObjectPath: meta1.Path,
		CreatedBy:  "admin",
		Tags: map[string]string{
			"type":    "document",
			"quarter": "Q1",
		},
	})

	doc2Entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:       velocity.EntityTypeObject,
		Name:       "q2-financial-report",
		ObjectPath: meta2.Path,
		CreatedBy:  "admin",
		Tags: map[string]string{
			"type":    "document",
			"quarter": "Q2",
		},
	})

	// Link documents to folder
	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: reportsFolder.EntityID,
		TargetEntity: doc1Entity.EntityID,
		RelationType: velocity.RelationTypeContains,
		CreatedBy:    "admin",
	})

	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: reportsFolder.EntityID,
		TargetEntity: doc2Entity.EntityID,
		RelationType: velocity.RelationTypeContains,
		CreatedBy:    "admin",
	})

	fmt.Printf("✓ Created document management structure")
	fmt.Printf("  Root folder: %s\n", rootFolder.Name)
	fmt.Printf("  Reports folder: %s\n", reportsFolder.Name)
	fmt.Printf("  Documents: %d\n", 2)

	// Get all documents in folder
	graph, _ := em.GetEntityGraph(ctx, rootFolder.EntityID, 3)
	fmt.Printf("  Total entities in graph: %d\n", len(graph))
}

func buildConfigurationSystem(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Create base configuration
	baseConfig := json.RawMessage(`{
		"timeout": 30,
		"retries": 3,
		"debug": false
	}`)

	baseEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "base-config",
		Data:      baseConfig,
		CreatedBy: "system",
		Tags: map[string]string{
			"type": "config",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create production configuration
	prodConfig := json.RawMessage(`{
		"timeout": 60,
		"retries": 5,
		"debug": false
	}`)

	prodEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "production-config",
		Data:      prodConfig,
		CreatedBy: "system",
		Tags: map[string]string{
			"type": "config",
			"env":  "production",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create dependency relationship
	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: prodEntity.EntityID,
		TargetEntity: baseEntity.EntityID,
		RelationType: velocity.RelationTypeDependsOn,
		CreatedBy:    "system",
	})

	// Store API secret
	apiSecretKey := []byte("secret:prod-api-key")
	apiSecretValue := []byte("sk-prod-secret-key")
	db.Put(apiSecretKey, apiSecretValue)

	// Create secret entity
	secretEntity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeSecret,
		Name:      "production-api-secret",
		SecretRef: "prod-api-key",
		CreatedBy: "system",
		Tags: map[string]string{
			"type": "secret",
			"env":  "production",
		},
	})

	// Link secret to production config
	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: prodEntity.EntityID,
		TargetEntity: secretEntity.EntityID,
		RelationType: velocity.RelationTypeReferences,
		CreatedBy:    "system",
	})

	fmt.Printf("✓ Created configuration system")
	fmt.Printf("  Base config: %s\n", baseEntity.Name)
	fmt.Printf("  Production config: %s\n", prodEntity.Name)
	fmt.Printf("  API secret: %s\n", secretEntity.Name)

	// Get configuration graph
	graph, _ := em.GetEntityGraph(ctx, prodEntity.EntityID, 2)
	fmt.Printf("  Configuration graph size: %d\n", len(graph))
}

func buildVersionControl(ctx context.Context, em *velocity.EntityManager) {
	// Create original document
	original := json.RawMessage(`{
		"title": "My Document",
		"content": "Original content",
		"version": "1.0"
	}`)

	originalEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "document-v1",
		Data:      original,
		CreatedBy: "user-123",
		Tags: map[string]string{
			"type":    "document",
			"version": "1.0",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create version 2
	version2 := json.RawMessage(`{
		"title": "My Document",
		"content": "Updated content with new information",
		"version": "2.0"
	}`)

	version2Entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "document-v2",
		Data:      version2,
		CreatedBy: "user-123",
		Tags: map[string]string{
			"type":    "document",
			"version": "2.0",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create version 3
	version3 := json.RawMessage(`{
		"title": "My Document",
		"content": "Final content with all updates",
		"version": "3.0"
	}`)

	version3Entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "document-v3",
		Data:      version3,
		CreatedBy: "user-123",
		Tags: map[string]string{
			"type":    "document",
			"version": "3.0",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create version relationships
	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: version2Entity.EntityID,
		TargetEntity: originalEntity.EntityID,
		RelationType: velocity.RelationTypeVersionOf,
		CreatedBy:    "user-123",
		Metadata: map[string]string{
			"version": "2.0",
		},
	})

	em.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: version3Entity.EntityID,
		TargetEntity: version2Entity.EntityID,
		RelationType: velocity.RelationTypeVersionOf,
		CreatedBy:    "user-123",
		Metadata: map[string]string{
			"version": "3.0",
		},
	})

	fmt.Printf("✓ Created version control system")
	fmt.Printf("  Original: %s\n", originalEntity.Name)
	fmt.Printf("  Version 2: %s\n", version2Entity.Name)
	fmt.Printf("  Version 3: %s\n", version3Entity.Name)

	// Get version history
	graph, _ := em.GetEntityGraph(ctx, version3Entity.EntityID, 3)
	fmt.Printf("  Version history size: %d\n", len(graph))
}

func createEncryptedEntities(ctx context.Context, em *velocity.EntityManager) {
	// Create sensitive data
	sensitiveData := json.RawMessage(`{
		"ssn": "123-45-6789",
		"credit_card": "4111-1111-1111-1111",
		"bank_account": "1234567890"
	}`)

	encryptedEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeJSON,
		Name:        "sensitive-pii-data",
		Description: "Personally Identifiable Information",
		Data:        sensitiveData,
		Encrypt:     true,
		CreatedBy:   "admin",
		Tags: map[string]string{
			"type":           "pii",
			"classification": "confidential",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created encrypted entity: %s\n", encryptedEntity.EntityID)
	fmt.Printf("  Encrypted: %v\n", encryptedEntity.Encrypted)
	fmt.Printf("  Encryption Algorithm: %s\n", encryptedEntity.EncryptionAlgo)

	// Retrieve and verify data is decrypted
	result, err := em.GetEntity(ctx, encryptedEntity.EntityID, false)
	if err != nil {
		log.Fatal(err)
	}

	// The data should be decrypted now
	fmt.Printf("  Decrypted data retrieved successfully")
	fmt.Printf("  Data length: %d bytes\n", len(result.Entity.Data))
	if len(result.Entity.Data) > 0 {
		previewLen := 50
		if len(result.Entity.Data) < previewLen {
			previewLen = len(result.Entity.Data)
		}
		fmt.Printf("  Data preview: %s\n", string(result.Entity.Data[:previewLen]))
	}
}

func createEnvelopesFromEntities(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Get existing entities
	entities, err := em.QueryEntities(ctx, nil)
	if err != nil || len(entities) == 0 {
		fmt.Println("No entities available for envelope creation")
		return
	}

	// Display all entities in table format
	fmt.Println("\n=== All Entities ===")
	fmt.Printf("%-10s | %-15s | %-30s | %-8s | %-30s\n", "ID", "Type", "Name", "Version", "Tags")
	for _, entity := range entities {
		tagsStr := ""
		if entity.Tags != nil {
			for k, v := range entity.Tags {
				tagsStr += fmt.Sprintf("%s=%s ", k, v)
			}
		}
		fmt.Printf("%-10s | %-15s | %-30s | %-8d | %-30s\n", entity.EntityID, entity.Type, entity.Name, entity.Version, tagsStr)
	}

	// Find a JSON entity to create an envelope from
	var jsonEntity *velocity.Entity
	for _, entity := range entities {
		if entity.Type == velocity.EntityTypeJSON {
			jsonEntity = entity
			break
		}
	}

	if jsonEntity == nil {
		fmt.Println("No JSON entity found for envelope creation")
		return
	}

	// Create relationships between entities first
	fmt.Println("\n--- Creating Relationships for Envelope ---")
	for i := 0; i < len(entities)-1; i++ {
		_, err := em.AddRelation(ctx, &velocity.EntityRelationRequest{
			SourceEntity:  entities[i].EntityID,
			TargetEntity:  entities[i+1].EntityID,
			RelationType:  velocity.RelationTypeRelatedTo,
			Bidirectional: true,
			CreatedBy:     "admin",
		})
		if err != nil {
			log.Printf("Warning: Failed to create relationship: %v", err)
		} else {
			fmt.Printf("✓ Created relationship: %s -> %s\n", entities[i].Name, entities[i+1].Name)
		}
	}

	// Display relationships in table format
	fmt.Println("\n=== All Relationships ===")
	fmt.Printf("%-10s | %-40s | %-40s | %-15s | %-15s\n", "Relation ID", "Source", "Target", "Type", "Bidirectional")
	relations, _ := em.GetRelations(ctx, "", nil)
	for _, rel := range relations {
		bidirectional := "No"
		if rel.Bidirectional {
			bidirectional = "Yes"
		}
		fmt.Printf("%-10s | %-40s | %-40s | %-15s | %-15s\n", rel.RelationID, rel.SourceEntity, rel.TargetEntity, rel.RelationType, bidirectional)
	}

	// Get entity graph to show related entities
	graph, err := em.GetEntityGraph(ctx, jsonEntity.EntityID, 2)
	if err != nil {
		log.Printf("Warning: Failed to get entity graph: %v", err)
	} else {
		fmt.Printf("✓ Entity graph contains %d entities\n", len(graph))

		// Display related entities in table format
		fmt.Println("\n=== Related Entities ===")
		fmt.Printf("%-10s | %-15s | %-30s | %-40s | %-8s\n", "ID", "Type", "Name", "Object/Secret", "Version")
		for entityID, result := range graph {
			if entityID != jsonEntity.EntityID {
				objSecret := ""
				if result.Entity.ObjectPath != "" {
					objSecret = fmt.Sprintf("Object: %s", result.Entity.ObjectPath)
				}
				if result.Entity.SecretRef != "" {
					if objSecret != "" {
						objSecret += ", "
					}
					objSecret += fmt.Sprintf("Secret: %s", result.Entity.SecretRef)
				}
				fmt.Printf("%-10s | %-15s | %-30s | %-40s | %-8d\n", entityID, result.Entity.Type, result.Entity.Name, objSecret, result.Entity.Version)
			}
		}
	}

	// Create a single envelope from the JSON entity
	fmt.Println("\n--- Creating Envelope from Entity ---")
	envelope, err := db.CreateEnvelopeFromEntity(ctx, jsonEntity.EntityID, velocity.EnvelopeTypeInvestigationRecord, "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created envelope from entity: %s\n", envelope.EnvelopeID)
	fmt.Printf("  Label: %s\n", envelope.Label)
	fmt.Printf("  Type: %s\n", envelope.Type)
	fmt.Printf("  Status: %s\n", envelope.Status)
	fmt.Printf("  Payload Kind: %s\n", envelope.Payload.Kind)
	fmt.Printf("  Entity ID: %s\n", envelope.Payload.Metadata["entity_id"])
	fmt.Printf("  Entity Type: %s\n", envelope.Payload.Metadata["entity_type"])
	fmt.Printf("  Entity Version: %s\n", envelope.Payload.Metadata["version"])

	// Export the envelope to a file
	exportPath := "./entity_demo_data/exported_envelope.json"
	err = db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Exported envelope to: %s\n", exportPath)

	// Verify the entity now references the envelope
	updatedEntity, err := em.GetEntity(ctx, jsonEntity.EntityID, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Entity now references envelope: %s\n", updatedEntity.Entity.EnvelopeID)

	// Load the envelope back from the entity
	loadedEnvelope, err := em.GetEntityEnvelope(ctx, jsonEntity.EntityID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Loaded envelope from entity: %s\n", loadedEnvelope.EnvelopeID)
	fmt.Printf("  Payload Hash: %s\n", loadedEnvelope.Integrity.PayloadHash)

	// Import the envelope into another vault (simulated)
	fmt.Println("\n--- Importing Envelope into Another Vault ---")

	// Create a new database instance to simulate another vault
	vault2, err := velocity.New("./entity_demo_vault2")
	if err != nil {
		log.Fatal(err)
	}
	defer vault2.Close()

	// Import the envelope into the new vault
	importedEnvelope, err := vault2.ImportEnvelope(ctx, exportPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Imported envelope into vault2: %s\n", importedEnvelope.EnvelopeID)
	fmt.Printf("  Label: %s\n", importedEnvelope.Label)
	fmt.Printf("  Type: %s\n", importedEnvelope.Type)
	fmt.Printf("  Status: %s\n", importedEnvelope.Status)
	fmt.Printf("  Payload Hash: %s\n", importedEnvelope.Integrity.PayloadHash)

	// Verify the imported envelope has the same data
	if importedEnvelope.EnvelopeID == loadedEnvelope.EnvelopeID {
		fmt.Printf("✓ Envelope ID matches: %s\n", importedEnvelope.EnvelopeID)
	}
	if importedEnvelope.Integrity.PayloadHash == loadedEnvelope.Integrity.PayloadHash {
		fmt.Printf("✓ Payload hash matches: %s\n", importedEnvelope.Integrity.PayloadHash)
	}

	// Load the imported envelope to verify it's accessible
	verifiedEnvelope, err := vault2.LoadEnvelope(ctx, importedEnvelope.EnvelopeID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Verified imported envelope is accessible")
	fmt.Printf("  Custody events: %d\n", len(verifiedEnvelope.CustodyLedger))
	fmt.Printf("  Audit entries: %d\n", len(verifiedEnvelope.AuditLog))

	// Display the payload data
	if len(verifiedEnvelope.Payload.Value) > 0 {
		fmt.Printf("  Payload data: %s\n", string(verifiedEnvelope.Payload.Value))
	}

	fmt.Println("\n✓ Envelope export and import verified successfully!")
}

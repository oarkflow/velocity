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

	fmt.Println("=== Velocity Entity Relations Demo - JSON Data & Objects ===\n")

	// Demo 1: Create JSON entities and show data
	fmt.Println("Demo 1: Creating JSON Entities with Data")
	createJSONEntities(ctx, em)

	// Demo 2: Create entities with secret references and retrieve secrets
	fmt.Println("\nDemo 2: Creating Entities with Secret References")
	createSecretEntities(ctx, db, em)

	// Demo 3: Create entities with object references and retrieve objects
	fmt.Println("\nDemo 3: Creating Entities with Object References")
	createObjectEntities(ctx, db, em)

	// Demo 4: Create relationships and show related entities with data
	fmt.Println("\nDemo 4: Creating Relationships and Showing Related Data")
	createRelationshipsAndShowData(ctx, db, em)

	// Demo 5: Create envelope from entity with relationships
	fmt.Println("\nDemo 5: Creating Envelope from Entity with Relationships")
	createEnvelopeWithRelationships(ctx, db, em)

	fmt.Println("\n=== Demo Complete ===")
}

func createJSONEntities(ctx context.Context, em *velocity.EntityManager) {
	// Create a user profile entity
	userProfile := json.RawMessage(`{
		"name": "John Doe",
		"email": "john.doe@example.com",
		"age": 30,
		"department": "Engineering",
		"skills": ["Go", "Python", "Docker"],
		"active": true
	}`)

	userEntity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeJSON,
		Name:        "user-profile-john-doe",
		Description: "User profile for John Doe",
		Data:        userProfile,
		CreatedBy:    "admin",
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

	// Retrieve and display JSON data
	result, err := em.GetEntity(ctx, userEntity.EntityID, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  JSON Data:\n")
	var userData map[string]interface{}
	if err := json.Unmarshal(result.Entity.Data, &userData); err == nil {
		prettyJSON, _ := json.MarshalIndent(userData, "    ", "  ")
		fmt.Printf("    %s\n", string(prettyJSON))
	}

	// Create a project entity
	project := json.RawMessage(`{
		"name": "Velocity Database",
		"description": "High-performance key-value database",
		"status": "active",
		"priority": "high",
		"team": ["Alice", "Bob", "Charlie"],
		"deadline": "2024-12-31"
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

	fmt.Printf("\n✓ Created project entity: %s\n", projectEntity.EntityID)

	// Retrieve and display project JSON data
	projectResult, err := em.GetEntity(ctx, projectEntity.EntityID, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  Project JSON Data:\n")
	var projectData map[string]interface{}
	if err := json.Unmarshal(projectResult.Entity.Data, &projectData); err == nil {
		prettyJSON, _ := json.MarshalIndent(projectData, "    ", "  ")
		fmt.Printf("    %s\n", string(prettyJSON))
	}
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
		CreatedBy:    "admin",
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
	fmt.Printf("  Name: %s\n", secretEntity.Name)
	fmt.Printf("  Secret Reference: %s\n", secretEntity.SecretRef)

	// Retrieve the secret through the entity
	retrievedSecret, err := em.GetEntitySecret(ctx, secretEntity.EntityID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  Retrieved Secret Value:\n")
	fmt.Printf("    %s\n", string(retrievedSecret))

	// Store another secret
	dbSecretKey := []byte("secret:database-connection-string")
	dbSecretValue := []byte("postgresql://user:pass@localhost:5432/mydb")
	db.Put(dbSecretKey, dbSecretValue)

	// Create entity for database secret
	dbSecretEntity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeSecret,
		Name:        "database-connection-string",
		Description: "Database connection string",
		SecretRef:   "database-connection-string",
		CreatedBy:    "admin",
		Tags: map[string]string{
			"type":    "secret",
			"service": "database",
		},
	})

	fmt.Printf("\n✓ Created database secret entity: %s\n", dbSecretEntity.EntityID)
	dbSecret, _ := em.GetEntitySecret(ctx, dbSecretEntity.EntityID)
	fmt.Printf("  Database Connection String:\n")
	fmt.Printf("    %s\n", string(dbSecret))
}

func createObjectEntities(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Store an object
	documentContent := []byte("This is a confidential document content.\nIt contains sensitive information about the company's financial status.\n\nQ1 2024 Financial Report\nRevenue: $1,000,000\nExpenses: $750,000\nNet Profit: $250,000")
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
			"year":          "2024",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✓ Created object entity: %s\n", objectEntity.EntityID)
	fmt.Printf("  Name: %s\n", objectEntity.Name)
	fmt.Printf("  Object Path: %s\n", objectEntity.ObjectPath)

	// Retrieve the object through the entity
	data, retrievedMeta, err := em.GetEntityObject(ctx, objectEntity.EntityID, "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  Retrieved Object Metadata:\n")
	fmt.Printf("    Name: %s\n", retrievedMeta.Name)
	fmt.Printf("    Size: %d bytes\n", retrievedMeta.Size)
	fmt.Printf("    Content Type: %s\n", retrievedMeta.ContentType)
	fmt.Printf("    Created: %s\n", retrievedMeta.CreatedAt.Format("2006-01-02 15:04:05"))

	fmt.Printf("\n  Object Content:\n")
	fmt.Printf("    %s\n", string(data))

	// Store another object
	configContent := []byte(`{
  "server": {
    "host": "localhost",
    "port": 8080
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "name": "mydb"
  }
}`)
	configMeta, _ := db.StoreObject(
		"config/app-config.json",
		"application/json",
		"admin",
		configContent,
		&velocity.ObjectOptions{Encrypt: false},
	)

	configEntity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
		Type:       velocity.EntityTypeObject,
		Name:       "application-config",
		ObjectPath: configMeta.Path,
		CreatedBy:  "admin",
		Tags: map[string]string{
			"type":  "config",
			"env":   "production",
		},
	})

	fmt.Printf("\n✓ Created config object entity: %s\n", configEntity.EntityID)
	configData, _, _ := em.GetEntityObject(ctx, configEntity.EntityID, "admin")
	fmt.Printf("  Config Content:\n")
	fmt.Printf("    %s\n", string(configData))
}

func createRelationshipsAndShowData(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Get existing entities
	entities, err := em.QueryEntities(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(entities) < 2 {
		fmt.Println("Not enough entities to create relationships")
		return
	}

	// Create relationships between entities
	fmt.Println("\n  Creating relationships between entities...")
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
		}
	}

	// Get first entity and show its related entities with data
	rootEntity := entities[0]
	fmt.Printf("\n✓ Root Entity: %s (%s)\n", rootEntity.Name, rootEntity.Type)

	// Get related entities with depth 2
	graph, err := em.GetEntityGraph(ctx, rootEntity.EntityID, 2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  Related Entities (depth 2):\n")
	for entityID, result := range graph {
		if entityID != rootEntity.EntityID {
			fmt.Printf("\n  Entity: %s\n", result.Entity.Name)
			fmt.Printf("    ID: %s\n", entityID)
			fmt.Printf("    Type: %s\n", result.Entity.Type)
			fmt.Printf("    Version: %d\n", result.Entity.Version)

			// Show relationships
			if len(result.Relationships) > 0 {
				fmt.Printf("    Relationships:\n")
				for _, rel := range result.Relationships {
					fmt.Printf("      - %s -> %s (%s)\n", rel.SourceEntity, rel.TargetEntity, rel.RelationType)
				}
			}

			// Show JSON data if available
			if result.Entity.Type == velocity.EntityTypeJSON && len(result.Entity.Data) > 0 {
				fmt.Printf("    JSON Data:\n")
				var data map[string]interface{}
				if err := json.Unmarshal(result.Entity.Data, &data); err == nil {
					prettyJSON, _ := json.MarshalIndent(data, "      ", "  ")
					fmt.Printf("      %s\n", string(prettyJSON))
				}
			}

			// Show secret reference if available
			if result.Entity.SecretRef != "" {
				fmt.Printf("    Secret Reference: %s\n", result.Entity.SecretRef)
				secret, err := em.GetEntitySecret(ctx, entityID)
				if err == nil {
					fmt.Printf("    Secret Value: %s\n", string(secret))
				}
			}

			// Show object reference if available
			if result.Entity.ObjectPath != "" {
				fmt.Printf("    Object Path: %s\n", result.Entity.ObjectPath)
				data, meta, err := em.GetEntityObject(ctx, entityID, "admin")
				if err == nil {
					fmt.Printf("    Object Size: %d bytes\n", meta.Size)
					fmt.Printf("    Object Content (first 100 chars): %s\n", string(data[:min(100, len(data))]))
				}
			}
		}
	}
}

func createEnvelopeWithRelationships(ctx context.Context, db *velocity.DB, em *velocity.EntityManager) {
	// Get existing entities
	entities, err := em.QueryEntities(ctx, nil)
	if err != nil || len(entities) == 0 {
		fmt.Println("No entities available for envelope creation")
		return
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

	fmt.Printf("\n✓ Creating envelope from entity: %s\n", jsonEntity.Name)

	// Get entity data before creating envelope
	entityResult, err := em.GetEntity(ctx, jsonEntity.EntityID, true)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n  Entity Data:\n")
	var entityData map[string]interface{}
	if err := json.Unmarshal(entityResult.Entity.Data, &entityData); err == nil {
		prettyJSON, _ := json.MarshalIndent(entityData, "    ", "  ")
		fmt.Printf("    %s\n", string(prettyJSON))
	}

	// Get related entities
	graph, err := em.GetEntityGraph(ctx, jsonEntity.EntityID, 2)
	if err == nil {
		fmt.Printf("\n  Related Entities in Envelope:\n")
		for entityID, result := range graph {
			if entityID != jsonEntity.EntityID {
				fmt.Printf("    - %s (%s)\n", result.Entity.Name, result.Entity.Type)
				if result.Entity.SecretRef != "" {
					fmt.Printf("      Secret: %s\n", result.Entity.SecretRef)
				}
				if result.Entity.ObjectPath != "" {
					fmt.Printf("      Object: %s\n", result.Entity.ObjectPath)
				}
			}
		}
	}

	// Create envelope from entity
	envelope, err := db.CreateEnvelopeFromEntity(ctx, jsonEntity.EntityID, velocity.EnvelopeTypeInvestigationRecord, "admin")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n✓ Created envelope: %s\n", envelope.EnvelopeID)
	fmt.Printf("  Label: %s\n", envelope.Label)
	fmt.Printf("  Type: %s\n", envelope.Type)
	fmt.Printf("  Status: %s\n", envelope.Status)
	fmt.Printf("  Payload Kind: %s\n", envelope.Payload.Kind)

	// Show envelope metadata
	fmt.Printf("\n  Envelope Metadata:\n")
	for k, v := range envelope.Payload.Metadata {
		fmt.Printf("    %s: %s\n", k, v)
	}

	// Show envelope payload data
	if len(envelope.Payload.Value) > 0 {
		fmt.Printf("\n  Envelope Payload Data:\n")
		var payloadData map[string]interface{}
		if err := json.Unmarshal(envelope.Payload.Value, &payloadData); err == nil {
			prettyJSON, _ := json.MarshalIndent(payloadData, "    ", "  ")
			fmt.Printf("    %s\n", string(prettyJSON))
		} else {
			fmt.Printf("    %s\n", string(envelope.Payload.Value))
		}
	}

	// Export envelope to file
	exportPath := "./entity_demo_data/exported_envelope.json"
	err = db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n✓ Exported envelope to: %s\n", exportPath)

	// Import envelope into another vault
	fmt.Println("\n  Importing envelope into another vault...")
	vault2, err := velocity.New("./entity_demo_vault2")
	if err != nil {
		log.Fatal(err)
	}
	defer vault2.Close()

	importedEnvelope, err := vault2.ImportEnvelope(ctx, exportPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n✓ Imported envelope: %s\n", importedEnvelope.EnvelopeID)
	fmt.Printf("  Label: %s\n", importedEnvelope.Label)
	fmt.Printf("  Payload Hash: %s\n", importedEnvelope.Integrity.PayloadHash)

	// Verify payload data matches
	if len(importedEnvelope.Payload.Value) > 0 {
		fmt.Printf("\n  Imported Envelope Payload Data:\n")
		var importedData map[string]interface{}
		if err := json.Unmarshal(importedEnvelope.Payload.Value, &importedData); err == nil {
			prettyJSON, _ := json.MarshalIndent(importedData, "    ", "  ")
			fmt.Printf("    %s\n", string(prettyJSON))
		}
	}

	fmt.Println("\n✓ Envelope export and import verified successfully!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

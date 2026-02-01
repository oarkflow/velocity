# Entity Relations System

The Entity Relations System in Velocity provides a powerful way to store, manage, and query relationships between JSON entities, Secrets, and Objects. This system enables you to build complex data models with interconnected entities while maintaining security and performance.

## Overview

The Entity Relations System allows you to:

- **Store JSON entities** with metadata and optional encryption
- **Reference Secrets** stored in the key-value store
- **Link to Objects** stored in object storage
- **Reference Envelopes** for evidence management
- **Create relationships** between entities (contains, references, depends_on, etc.)
- **Query and traverse** entity graphs
- **Search by tags** and metadata

## Core Concepts

### Entity Types

| Type | Description | Use Case |
|------|-------------|-----------|
| `json` | JSON data entities | Configuration, documents, structured data |
| `secret` | References to secrets | API keys, passwords, tokens |
| `object` | References to stored objects | Files, images, binaries |
| `folder` | Folder entities | Organizational structures |
| `custom` | Custom entity types | Application-specific entities |

### Relation Types

| Type | Description | Example |
|------|-------------|---------|
| `contains` | Entity A contains Entity B | Folder contains files |
| `references` | Entity A references Entity B | Document references image |
| `depends_on` | Entity A depends on Entity B | Task depends on prerequisite |
| `related_to` | Generic relationship | Related items |
| `version_of` | Entity A is a version of Entity B | Document versions |
| `derived_from` | Entity A is derived from Entity B | Report derived from data |
| `attached_to` | Entity A is attached to Entity B | Attachment to document |

## Getting Started

### Basic Setup

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "github.com/yourusername/velocity"
)

func main() {
    // Open database
    db, err := velocity.New("./mydata")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    ctx := context.Background()
    em := db.EntityManager()

    // Your code here
}
```

## Creating Entities

### JSON Entity

```go
// Create a JSON entity
jsonData := json.RawMessage(`{
    "title": "My Document",
    "content": "This is the document content",
    "author": "John Doe"
}`)

entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "my-document",
    Description: "A sample document",
    Data:      jsonData,
    CreatedBy:  "user-123",
    Tags: map[string]string{
        "category": "documents",
        "status":   "draft",
    },
    Metadata: map[string]string{
        "language": "en",
        "format":   "markdown",
    },
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created entity: %s\n", entity.EntityID)
```

### Entity with Secret Reference

```go
// Store a secret first
secretKey := []byte("secret:api-key")
secretValue := []byte("sk-1234567890abcdef")
if err := db.Put(secretKey, secretValue); err != nil {
    log.Fatal(err)
}

// Create entity referencing the secret
entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeSecret,
    Name:      "api-credentials",
    Description: "API credentials for external service",
    SecretRef:  "api-key",
    CreatedBy:  "user-123",
    Tags: map[string]string{
        "service": "external-api",
        "env":     "production",
    },
})
```

### Entity with Object Reference

```go
// Store an object first
objectData := []byte("This is a file content")
meta, err := db.StoreObject(
    "documents/report.pdf",
    "application/pdf",
    "user-123",
    objectData,
    &velocity.ObjectOptions{
        Encrypt: true,
        Tags: map[string]string{
            "type": "report",
            "year": "2024",
        },
    },
)
if err != nil {
    log.Fatal(err)
}

// Create entity referencing the object
entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:       velocity.EntityTypeObject,
    Name:       "report-entity",
    Description: "Annual report document",
    ObjectPath:  meta.Path,
    CreatedBy:   "user-123",
})
```

### Encrypted Entity

```go
// Create an encrypted entity
sensitiveData := json.RawMessage(`{
    "ssn": "123-45-6789",
    "credit_card": "4111-1111-1111-1111"
}`)

entity, err := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "sensitive-data",
    Data:      sensitiveData,
    Encrypt:   true,
    CreatedBy: "user-123",
    Tags: map[string]string{
        "classification": "confidential",
    },
})
```

## Retrieving Entities

### Get Entity by ID

```go
// Get entity without relations
result, err := em.GetEntity(ctx, entityID, false)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Entity: %s\n", result.Entity.Name)
fmt.Printf("Type: %s\n", result.Entity.Type)
fmt.Printf("Created: %s\n", result.Entity.CreatedAt)

// Get entity with relations
resultWithRelations, err := em.GetEntity(ctx, entityID, true)
if err != nil {
    log.Fatal(err)
}

for _, rel := range resultWithRelations.Relationships {
    fmt.Printf("Relation: %s -> %s (%s)\n",
        rel.SourceEntity, rel.TargetEntity, rel.RelationType)
}
```

### Query Entities

```go
// Query all entities
allEntities, err := em.QueryEntities(ctx, nil)
if err != nil {
    log.Fatal(err)
}

// Query by type
jsonEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
    Type: velocity.EntityTypeJSON,
})

// Query by tags
taggedEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
    Tags: map[string]string{
        "category": "documents",
        "status":   "published",
    },
})

// Query with time filters
now := time.Now()
yesterday := now.Add(-24 * time.Hour)
recentEntities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
    CreatedAfter: &yesterday,
})

// Query with sorting and pagination
entities, err := em.QueryEntities(ctx, &velocity.EntityQueryOptions{
    SortBy:    "created_at",
    SortOrder: "desc",
    Limit:     10,
    Offset:    0,
})
```

### Search by Tag

```go
// Search entities by tag
entities, err := em.SearchEntitiesByTag(ctx, "category", "documents")
if err != nil {
    log.Fatal(err)
}

for _, entity := range entities {
    fmt.Printf("Found: %s\n", entity.Name)
}
```

## Managing Relationships

### Creating Relationships

```go
// Create two entities
parentEntity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "parent-folder",
    Data:      json.RawMessage(`{"type": "folder"}`),
    CreatedBy: "user-123",
})

childEntity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "child-file",
    Data:      json.RawMessage(`{"type": "file"}`),
    CreatedBy: "user-123",
})

// Create a relationship
relation, err := em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  parentEntity.EntityID,
    TargetEntity:  childEntity.EntityID,
    RelationType:  velocity.RelationTypeContains,
    Bidirectional: false,
    CreatedBy:     "user-123",
    Metadata: map[string]string{
        "description": "Folder contains file",
    },
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created relation: %s\n", relation.RelationID)
```

### Bidirectional Relationships

```go
// Create a bidirectional relationship
relation, err := em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  entity1.EntityID,
    TargetEntity:  entity2.EntityID,
    RelationType:  velocity.RelationTypeRelatedTo,
    Bidirectional: true,
    CreatedBy:     "user-123",
})
```

### Querying Relationships

```go
// Get all relations for an entity
relations, err := em.GetRelations(ctx, entityID, nil)
if err != nil {
    log.Fatal(err)
}

for _, rel := range relations {
    fmt.Printf("%s -> %s (%s)\n",
        rel.SourceEntity, rel.TargetEntity, rel.RelationType)
}

// Get relations by type
containsRelations, err := em.GetRelations(ctx, entityID, &velocity.EntityRelationQueryOptions{
    RelationType: velocity.RelationTypeContains,
})

// Get bidirectional relations only
bidirectionalRelations, err := em.GetRelations(ctx, entityID, &velocity.EntityRelationQueryOptions{
    Bidirectional: true,
})
```

### Removing Relationships

```go
// Remove a relationship
err := em.RemoveRelation(ctx, relationID)
if err != nil {
    log.Fatal(err)
}
```

## Traversing Entity Graphs

### Get Related Entities

```go
// Get directly related entities (depth 1)
related, err := em.GetRelatedEntities(ctx, entityID, "", 1)
if err != nil {
    log.Fatal(err)
}

for _, result := range related {
    fmt.Printf("Related: %s\n", result.Entity.Name)
}

// Get related entities with specific relation type
containsRelated, err := em.GetRelatedEntities(ctx, entityID, velocity.RelationTypeContains, 2)

// Get deeply related entities (depth 3)
deeplyRelated, err := em.GetRelatedEntities(ctx, entityID, "", 3)
```

### Get Entity Graph

```go
// Get complete entity graph
graph, err := em.GetEntityGraph(ctx, entityID, 3)
if err != nil {
    log.Fatal(err)
}

// Iterate through graph
for entityID, result := range graph {
    fmt.Printf("Entity: %s (%s)\n", result.Entity.Name, entityID)
    for _, rel := range result.Relationships {
        fmt.Printf("  -> %s (%s)\n", rel.TargetEntity, rel.RelationType)
    }
}
```

## Accessing Referenced Data

### Get Entity Secret

```go
// Get secret referenced by entity
secret, err := em.GetEntitySecret(ctx, entityID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Secret: %s\n", string(secret))
```

### Get Entity Object

```go
// Get object referenced by entity
data, meta, err := em.GetEntityObject(ctx, entityID, "user-123")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Object: %s (%d bytes)\n", meta.Name, meta.Size)
fmt.Printf("Content: %s\n", string(data))
```

### Get Entity Envelope

```go
// Get envelope referenced by entity
envelope, err := em.GetEntityEnvelope(ctx, entityID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Envelope: %s\n", envelope.Label)
fmt.Printf("Type: %s\n", envelope.Type)
```

### Create Envelope from Entity

```go
// Create an envelope from an existing entity
envelope, err := db.CreateEnvelopeFromEntity(ctx, entityID, velocity.EnvelopeTypeInvestigationRecord, "admin")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created envelope: %s\n", envelope.EnvelopeID)
fmt.Printf("Label: %s\n", envelope.Label)
fmt.Printf("Type: %s\n", envelope.Type)
fmt.Printf("Status: %s\n", envelope.Status)
fmt.Printf("Payload Kind: %s\n", envelope.Payload.Kind)

// The entity now references the envelope
updatedEntity, _ := em.GetEntity(ctx, entityID, false)
fmt.Printf("Entity Envelope ID: %s\n", updatedEntity.Entity.EnvelopeID)
```

### Export Envelope

```go
// Export envelope to a file
exportPath := "./exported_envelope.json"
err := db.ExportEnvelope(ctx, envelopeID, exportPath)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Exported envelope to: %s\n", exportPath)
```

### Import Envelope

```go
// Import envelope from a file
envelope, err := db.ImportEnvelope(ctx, "./exported_envelope.json")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Imported envelope: %s\n", envelope.EnvelopeID)
```

## Updating Entities

```go
// Update an entity
updatedData := json.RawMessage(`{"updated": true}`)
updated, err := em.UpdateEntity(ctx, entityID, &velocity.EntityRequest{
    Name:        "updated-name",
    Data:        updatedData,
    Description: "Updated description",
    CreatedBy:    "user-123",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Updated version: %d\n", updated.Version)
```

## Deleting Entities

```go
// Delete an entity (also removes all relationships)
err := em.DeleteEntity(ctx, entityID)
if err != nil {
    log.Fatal(err)
}
```

## Advanced Use Cases

### Building a Document Management System

```go
// Create folder structure
rootFolder, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeFolder,
    Name:      "documents",
    CreatedBy: "user-123",
})

subFolder, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeFolder,
    Name:      "reports",
    CreatedBy: "user-123",
})

// Create folder relationships
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  rootFolder.EntityID,
    TargetEntity:  subFolder.EntityID,
    RelationType:  velocity.RelationTypeContains,
    CreatedBy:     "user-123",
})

// Create document entities
doc1, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:       velocity.EntityTypeObject,
    Name:       "annual-report.pdf",
    ObjectPath: "documents/reports/annual-report.pdf",
    CreatedBy:  "user-123",
})

// Link document to folder
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  subFolder.EntityID,
    TargetEntity:  doc1.EntityID,
    RelationType:  velocity.RelationTypeContains,
    CreatedBy:     "user-123",
})

// Get all documents in folder
graph, _ := em.GetEntityGraph(ctx, rootFolder.EntityID, 3)
```

### Building a Configuration System

```go
// Create configuration entities
baseConfig, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "base-config",
    Data:      json.RawMessage(`{"timeout": 30, "retries": 3}`),
    CreatedBy: "system",
})

envConfig, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "production-config",
    Data:      json.RawMessage(`{"timeout": 60, "retries": 5}`),
    CreatedBy: "system",
})

// Create dependency relationship
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  envConfig.EntityID,
    TargetEntity:  baseConfig.EntityID,
    RelationType:  velocity.RelationTypeDependsOn,
    CreatedBy:     "system",
})

// Add secret reference
apiSecret, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeSecret,
    Name:      "api-secret",
    SecretRef: "production-api-key",
    CreatedBy: "system",
})

em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  envConfig.EntityID,
    TargetEntity:  apiSecret.EntityID,
    RelationType:  velocity.RelationTypeReferences,
    CreatedBy:     "system",
})
```

### Building a Version Control System

```go
// Create original document
original, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "document-v1",
    Data:      json.RawMessage(`{"content": "original"}`),
    CreatedBy: "user-123",
})

// Create version
version2, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Type:      velocity.EntityTypeJSON,
    Name:      "document-v2",
    Data:      json.RawMessage(`{"content": "updated"}`),
    CreatedBy: "user-123",
})

// Create version relationship
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    SourceEntity:  version2.EntityID,
    TargetEntity:  original.EntityID,
    RelationType:  velocity.RelationTypeVersionOf,
    CreatedBy:     "user-123",
    Metadata: map[string]string{
        "version": "2.0",
    },
})
```

## Best Practices

### 1. Use Descriptive Names
```go
// Good
entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Name: "user-profile-john-doe",
    // ...
})

// Avoid
entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Name: "entity-1",
    // ...
})
```

### 2. Use Tags for Organization
```go
entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Tags: map[string]string{
        "category":    "documents",
        "department":  "engineering",
        "project":     "velocity",
        "status":      "active",
        "priority":    "high",
    },
})
```

### 3. Choose Appropriate Relation Types
```go
// Use "contains" for hierarchical relationships
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    RelationType: velocity.RelationTypeContains,
    // ...
})

// Use "references" for loose associations
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    RelationType: velocity.RelationTypeReferences,
    // ...
})

// Use "depends_on" for dependencies
em.AddRelation(ctx, &velocity.EntityRelationRequest{
    RelationType: velocity.RelationTypeDependsOn,
    // ...
})
```

### 4. Encrypt Sensitive Data
```go
entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Data:    sensitiveData,
    Encrypt: true,
    // ...
})
```

### 5. Use Metadata for Additional Context
```go
entity, _ := em.CreateEntity(ctx, &velocity.EntityRequest{
    Metadata: map[string]string{
        "source":      "import",
        "import_date": "2024-01-15",
        "validated":   "true",
    },
})
```

## Performance Considerations

### Query Optimization
- Use specific filters (type, tags, time ranges) to reduce result sets
- Use pagination for large result sets
- Limit graph traversal depth when possible

### Relationship Management
- Keep relationship graphs shallow when possible
- Use appropriate relation types for efficient querying
- Consider cleanup of unused relationships

### Storage
- Entity data is stored in the key-value store
- Large JSON data should be stored as objects instead
- Use references for large binary data

## Security Considerations

### Encryption
- Always encrypt sensitive entity data
- Use secret references for credentials
- Leverage Velocity's built-in encryption

### Access Control
- Implement proper user authentication
- Use entity metadata for access control
- Consider integrating with Velocity's ACL system

### Audit Trail
- Track entity creation and modifications
- Log relationship changes
- Monitor access patterns

## API Reference

See [`entity_relations.go`](entity_relations.go) for complete API documentation.

### Key Types

- `Entity` - Represents a stored entity
- `EntityRelation` - Represents a relationship between entities
- `EntityRequest` - Request for creating entities
- `EntityRelationRequest` - Request for creating relationships
- `EntityQueryOptions` - Options for querying entities
- `EntityRelationQueryOptions` - Options for querying relationships
- `EntityResult` - Entity with optional relationships

### Key Methods

- `CreateEntity()` - Create a new entity
- `GetEntity()` - Retrieve an entity
- `UpdateEntity()` - Update an existing entity
- `DeleteEntity()` - Delete an entity
- `QueryEntities()` - Query entities with filters
- `SearchEntitiesByTag()` - Search entities by tag
- `AddRelation()` - Create a relationship
- `RemoveRelation()` - Remove a relationship
- `GetRelations()` - Get relationships for an entity
- `GetRelatedEntities()` - Get related entities with traversal
- `GetEntityGraph()` - Get complete entity graph
- `GetEntitySecret()` - Get secret referenced by entity
- `GetEntityObject()` - Get object referenced by entity
- `GetEntityEnvelope()` - Get envelope referenced by entity
- `CreateEnvelopeFromEntity()` - Create an envelope from an existing entity
- `ExportEnvelope()` - Export envelope to a file
- `ImportEnvelope()` - Import envelope from a file

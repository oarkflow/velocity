# Knowledge Graph

Velocity includes a knowledge graph subsystem for document ingestion, text extraction, chunking, entity detection, graph relations, vector search, and analytics.

## Embedded API

Access the engine through:

```go
kg := db.KnowledgeGraph()
```

The engine exposes ingestion, batch ingestion, document lookup/deletion, search, graph neighbors, and analytics behavior.

## Ingestion

Ingestion accepts `KGIngestRequest` values with content, source, media type, title, and metadata. The default extractor supports plain text, HTML, JSON, and empty-content handling.

The HTTP API accepts JSON or multipart uploads at:

- `POST /api/v1/kg/ingest`
- `POST /api/v1/kg/ingest/batch`

## Chunking

`SlidingWindowChunker` splits documents by word windows with overlap and tracks byte offsets.

## Entity Extraction

Rule-based NER supports tests for:

- Email
- URL
- Date
- Money
- Organization
- Person
- Deduplication
- Custom rules

## Entity Management

The entity manager supports:

- Create, get, update, delete, and query entities.
- Add, remove, and query relations.
- Bidirectional relation handling.
- Related entity traversal by depth.
- Entity graph retrieval.
- Tag search.
- Links to secrets, objects, and envelopes.

## Vector And Hybrid Search

The KG subsystem includes:

- HNSW index.
- Cosine similarity.
- Float32 vector encoding/decoding.
- Insert, search, and delete behavior.
- Dimension mismatch validation.
- Search modes and reranker interfaces.

## HTTP API

Routes:

- `POST /api/v1/kg/ingest`
- `POST /api/v1/kg/ingest/batch`
- `POST /api/v1/kg/search`
- `GET /api/v1/kg/documents/:id`
- `DELETE /api/v1/kg/documents/:id`
- `GET /api/v1/kg/graph/:entity_id?depth=1`
- `GET /api/v1/kg/analytics`

## Examples

- `examples/kg_cookbook/main.go`
- `examples/kg_batch_demo/main.go`
- `examples/kg_ner_demo/main.go`
- `examples/kg_search_demo/main.go`
- `examples/entity_relations_demo/main.go`


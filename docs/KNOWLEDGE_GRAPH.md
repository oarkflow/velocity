# Knowledge Graph

Velocity includes an embedded knowledge graph subsystem for turning Velocity resources into searchable, connected knowledge. Its primary purpose is to identify a relationship graph between records, objects, secrets, SQL rows, envelopes, entities, and ingested documents by searching or querying their content and metadata.

## What It Is

A knowledge graph is a structured layer over unstructured content. Instead of storing a document only as bytes, Velocity can break it into searchable chunks and extract meaningful entities such as people, organizations, emails, URLs, dates, and money values. Those documents, chunks, entities, and relationships can then be searched and analyzed.

In Velocity, the KG is embedded in the same storage engine as the KV store, object system, secrets, SQL driver, and compliance features. That means an application can keep operational data and knowledge data together without deploying a separate search service for basic use cases.

## Purpose

Use the knowledge graph when you want to answer questions like:

- Which documents mention a customer, company, person, email, or project?
- Which Velocity resources are related to the same customer, case, policy, account, or identifier?
- What records, objects, secrets, SQL rows, envelopes, and entities are connected by a search query?
- Which chunks are most relevant to a search query?
- What entities were discovered during ingestion?
- Which records are related to an entity?
- How many documents, chunks, and entities are in the corpus?
- Can I build a local RAG or investigation workflow without external infrastructure?

Good fits:

- Compliance evidence search.
- Case management and investigation systems.
- Local RAG/document intelligence.
- Customer, contract, policy, or support knowledge bases.
- Entity-centric applications that connect records, secrets, objects, and envelopes.

## What It Can Perform

The KG subsystem can perform these workflows:

- Ingest one document with `KGIngestRequest`.
- Batch ingest multiple documents with `IngestBatch`.
- Extract text from plain text, HTML, and JSON inputs.
- Chunk long content with a sliding window.
- Extract entities with the rule-based NER engine.
- Deduplicate and resolve similar entities.
- Store and retrieve ingested document metadata.
- Delete documents and related KG records.
- Search by keyword.
- Search with full-text match modes, including all terms, any terms, boolean `OR`, quoted phrases, and prefix matching.
- Use opt-in fuzzy matching for typo-tolerant fallback search.
- Search by vector or hybrid mode when an embedder/HNSW index is configured.
- Filter searches by metadata.
- Return a resource relation graph from a query with `SearchResourceGraph`.
- Rerank search hits with a custom reranker.
- Traverse entity relationships.
- Return corpus analytics.

## How It Works

The pipeline is:

1. Ingest content with source, media type, title, and metadata.
2. Extract text from the content.
3. Split text into overlapping chunks.
4. Extract entities from each chunk.
5. Store documents, chunks, entities, and search index entries.
6. Optionally embed chunks and index vectors in HNSW.
7. Search by keyword, semantic vector, or hybrid scoring.
8. Use analytics and graph traversal to understand the corpus.

## Run The Demo

Run the focused shell walkthrough:

```bash
./scripts/knowledge_graph_demo.sh
```

Run it through the wrapper:

```bash
./scripts/velocity.sh demo kg
```

Include the larger synthetic batch benchmark:

```bash
KG_RUN_BATCH=1 ./scripts/knowledge_graph_demo.sh
```

The script runs:

- `examples/kg_search_demo`
- `examples/kg_cookbook`
- an inline embedded KG API example
- focused KG tests

## Expected Result

The demo prints output like:

```text
Ingested: annual-report-2024.txt -> docID=... chunks=1 entities=10
Results: 1 hits in 0ms (mode: keyword)
Total documents: 5
Total chunks: 5
Total entities: 25
filtered search hits: 1 mode=keyword
delete verified: analytics-note removed
```

The exact IDs and timings change every run. A successful run ends with:

```text
Knowledge graph demo completed
```

## Embedded Go Usage

Create a KG engine from an open Velocity DB:

```go
db, err := velocity.New("./velocity_data")
if err != nil {
	log.Fatal(err)
}
defer db.Close()

kg := db.KnowledgeGraph(velocity.KGConfig{
	ChunkMaxWords: 64,
	ChunkOverlap:  16,
	IngestWorkers: 4,
})
if kg == nil {
	log.Fatal("knowledge graph unavailable")
}
```

Ingest a document:

```go
resp, err := kg.Ingest(ctx, &velocity.KGIngestRequest{
	Source:    "policy.txt",
	MediaType: "text/plain",
	Title:     "Retention Policy",
	Content:   []byte("Records are retained for seven years. Contact compliance@example.test."),
	Metadata: map[string]string{
		"department": "compliance",
		"year":       "2026",
	},
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(resp.DocID, resp.ChunkCount, resp.EntityCount)
```

Search the corpus:

```go
results, err := kg.Search(ctx, &velocity.KGSearchRequest{
	Query:   "retention compliance",
	Limit:   10,
	Mode:    velocity.KGSearchModeKeyword,
	Filters: map[string]string{"department": "compliance"},
})
if err != nil {
	log.Fatal(err)
}

for _, hit := range results.Hits {
	fmt.Println(hit.Source, hit.Title, hit.Score)
}
```

Use richer full-text and typo-tolerant search:

```go
phrase, _ := kg.Search(ctx, &velocity.KGSearchRequest{
	Query:     `"retention policy"`,
	MatchMode: "phrase",
	Limit:     10,
})

prefix, _ := kg.Search(ctx, &velocity.KGSearchRequest{
	Query:       "compli* reten*",
	PrefixMatch: true,
	Limit:       10,
})

fuzzy, _ := kg.Search(ctx, &velocity.KGSearchRequest{
	Query:         "complaince retenton",
	Fuzzy:         true,
	FuzzyMaxEdits: 1,
	Limit:         10,
})

fmt.Println(phrase.TotalHits, prefix.TotalHits, fuzzy.TotalHits)
```

Performance notes:

- Default keyword, phrase, boolean, and prefix search use a KG-specific in-memory chunk index backed by Velocity's persisted chunk records.
- The in-memory index keeps per-chunk text, tokens, normalized text, and term postings to avoid repeated JSON hydration and query-time tokenization.
- Fuzzy search is opt-in because it may scan KG chunks as a typo-tolerant fallback.
- KG chunks now persist extracted entities in chunk metadata, so resource graph queries can hydrate relationships without re-running NER on every hit.
- For large imports, batch ingest or disable online indexing during bulk loads, then rebuild derived indexes where appropriate.

Local benchmark command:

```bash
go test -bench 'BenchmarkKGSearchPerformance' -benchmem -run '^$' .
```

Recent local baseline on a 200-document KG corpus:

```text
keyword        ~23 us/op   ~38 KB/op   ~61 allocs/op
resource graph ~44 us/op   ~77 KB/op   ~332 allocs/op
fuzzy         ~180 us/op   ~75 KB/op   ~460 allocs/op
```

Retrieve and delete a document:

```go
doc, err := kg.GetDocument(resp.DocID)
if err != nil {
	log.Fatal(err)
}
fmt.Println(doc.Source, doc.ChunkCount, doc.EntityCount)

if err := kg.DeleteDocument(resp.DocID); err != nil {
	log.Fatal(err)
}
```

Read analytics:

```go
analytics := kg.GetAnalytics()
fmt.Println(analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)
```

## Automatic Resource Indexing

Applications can opt in to automatic KG indexing so normal Velocity writes become searchable without calling `Ingest` per record. This covers KV records, objects, secrets, SQL rows, envelopes, and entity records.

Enable it at open time for background sync of existing data and automatic indexing of future writes:

```go
db, err := velocity.NewWithConfig(velocity.Config{
	Path:                                "./velocity_data",
	KnowledgeGraphAutoIndexEnabled:     true,
	KnowledgeGraphAutoIndexResources:   []velocity.KGResourceType{velocity.KGResourceKV, velocity.KGResourceObject, velocity.KGResourceSecret},
	KnowledgeGraphAutoIndexMaxValueBytes: 1 << 20,
})
if err != nil {
	log.Fatal(err)
}
defer db.Close()
```

Or enable it on an already-open DB with explicit behavior:

```go
db.EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
	Enabled:       true,
	Resources:     []velocity.KGResourceType{velocity.KGResourceKV, velocity.KGResourceObject, velocity.KGResourceSecret, velocity.KGResourceSQLRow, velocity.KGResourceEnvelope, velocity.KGResourceEntity},
	SecretValues:  true,
	Existing:      true,
	Async:         true,
	MaxValueBytes: 1 << 20,
})
```

After that, use ordinary APIs:

```go
_ = db.Put([]byte("customers/123"), []byte("Acme renewal notes mention HIPAA review."))

_, _ = db.StoreObject("reports/q1.txt", "text/plain", "alice", []byte("Quarterly risk report for Acme."), nil)

_, _ = db.CreateSecret(ctx, velocity.SecretRequest{
	Name:  "acme-api-key",
	Value: []byte("secret token used by Acme integration"),
	Owner: "alice",
})

_, _ = db.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
	Label:     "Acme investigation",
	Type:      velocity.EnvelopeTypeInvestigationRecord,
	CreatedBy: "alice",
	Payload: velocity.EnvelopePayload{
		Kind:       "note",
		InlineData: []byte("Envelope evidence mentions Acme risk review."),
	},
})
```

Search the KG normally:

```go
resp, err := db.KnowledgeGraph().Search(ctx, &velocity.KGSearchRequest{
	Query: "Acme HIPAA risk",
	Limit: 10,
	Mode:  velocity.KGSearchModeKeyword,
})
if err != nil {
	log.Fatal(err)
}

for _, hit := range resp.Hits {
	fmt.Println(hit.Source, hit.Metadata["resource_type"], hit.Metadata["key"], hit.Metadata["path"])
}
```

Query the relationship graph between matching resources:

```go
graph, err := db.KnowledgeGraph().SearchResourceGraph(ctx, &velocity.KGResourceGraphRequest{
	Query: "Acme HIPAA risk",
	Limit: 10,
	Mode:  velocity.KGSearchModeKeyword,
})
if err != nil {
	log.Fatal(err)
}

for _, node := range graph.Nodes {
	fmt.Println("node", node.Source, node.ResourceType, node.ResourceID)
}
for _, edge := range graph.Edges {
	fmt.Println("edge", edge.Source, "->", edge.Target, edge.RelationType, edge.Entity.Canonical)
}
```

Resource graph behavior:

- Nodes are query-matching Velocity resources.
- Edges are inferred when resources share extracted entities such as organizations, emails, URLs, dates, money values, phone numbers, SSNs, or other configured NER rules.
- The default inferred relation is `mentions_same_entity`.
- Use this when the question is not only “what matched?” but “which matching resources are connected, and why?”.

Typical sources and metadata:

```text
kv:customers/123        resource_type=kv      key=customers/123
object:reports/q1.txt   resource_type=object  path=reports/q1.txt content_type=text/plain
secret:acme-api-key:v1  resource_type=secret  name=acme-api-key version=v1
envelope:env-...        resource_type=envelope envelope_id=env-...
entity:ent-...          resource_type=entity  entity_id=ent-...
sql:patients:patients:1 resource_type=sql_row table=patients row_key=patients:1
```

Manual sync is available when you want to scan existing resources on demand:

```go
if err := db.SyncKnowledgeGraph(ctx); err != nil {
	log.Fatal(err)
}
status := db.KnowledgeGraphSyncStatus()
fmt.Println(status.Running, status.Indexed, status.Skipped, status.LastError)
```

Important behavior:

- Auto-indexing is opt-in.
- Config-open auto-indexing starts a background scan of existing data.
- Public `EnableKnowledgeGraphAutoIndex` can run sync synchronously by setting `Async: false`.
- Stable source IDs make updates idempotent: the old KG document for a source is removed before the new representation is indexed.
- Deletes remove the corresponding KG document where Velocity owns the delete path.
- Large or binary content is indexed as metadata-only when it exceeds `MaxValueBytes` or is not text-like.
- Secret values are indexed when `SecretValues: true`; disable this for deployments where KG search must not expose secret text.

## Batch Ingestion

Batch ingestion is useful for import jobs:

```go
docs := []*velocity.KGIngestRequest{
	{
		Source:    "a.txt",
		MediaType: "text/plain",
		Title:     "A",
		Content:   []byte("Alice works with Acme Corp."),
	},
	{
		Source:    "b.txt",
		MediaType: "text/plain",
		Title:     "B",
		Content:   []byte("Bob manages the security project."),
	},
}

responses, errs := kg.IngestBatch(ctx, docs)
for i, err := range errs {
	if err != nil {
		log.Printf("document %d failed: %v", i, err)
		continue
	}
	fmt.Println(responses[i].DocID)
}
```

## Search Modes

Velocity exposes these KG search modes:

- `KGSearchModeKeyword`: BM25-like keyword search over stored chunks.
- `KGSearchModeSemantic`: vector search when an embedder and HNSW index are configured.
- `KGSearchModeHybrid`: combines keyword and vector signals.

Keyword search works without an external embedding service. Vector and hybrid search require embedding configuration or custom embedder wiring, as shown in `examples/kg_cookbook/main.go`.

## Entity And Graph Features

The KG works alongside Velocity's entity manager. You can create structured entities, attach relations, and traverse graphs:

```go
a, _ := db.CreateEntity(ctx, &velocity.EntityRequest{
	Type:      velocity.EntityTypeJSON,
	Name:      "customer-123",
	Data:      json.RawMessage(`{"name":"Acme Corp"}`),
	CreatedBy: "system",
})

b, _ := db.CreateEntity(ctx, &velocity.EntityRequest{
	Type:      velocity.EntityTypeJSON,
	Name:      "contract-456",
	Data:      json.RawMessage(`{"value":"100000"}`),
	CreatedBy: "system",
})

_, _ = db.AddRelation(ctx, &velocity.EntityRelationRequest{
	SourceEntity: a.EntityID,
	TargetEntity: b.EntityID,
	RelationType: velocity.RelationTypeReferences,
	CreatedBy:    "system",
})

graph, _ := db.GetEntityGraph(ctx, a.EntityID, 2)
fmt.Println(len(graph))
```

## HTTP API

The web module exposes KG routes:

- `POST /api/v1/kg/ingest`
- `POST /api/v1/kg/ingest/batch`
- `POST /api/v1/kg/search`
- `GET /api/v1/kg/documents/:id`
- `DELETE /api/v1/kg/documents/:id`
- `GET /api/v1/kg/graph/:entity_id?depth=1`
- `GET /api/v1/kg/analytics`

Example request shape:

```bash
curl -X POST http://localhost:8081/api/v1/kg/search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"retention compliance","limit":5,"mode":"keyword"}'
```

Authentication depends on the web server configuration. See [API Reference](API_REFERENCE.md) and [Operations](OPERATIONS.md).

## Limitations

- Keyword mode is the default local path.
- Vector and hybrid search need an embedder/HNSW setup.
- The built-in NER is rule-based; domain-specific extraction may need custom rules or a custom NER engine.
- KG is embedded; very large corpora should be benchmarked with realistic data before production use.
- The shipped `cmd/velocity` CLI does not expose first-class KG commands yet; use Go APIs, HTTP APIs, examples, or `scripts/knowledge_graph_demo.sh`.

## Source Examples

- `examples/kg_cookbook/main.go`
- `examples/kg_batch_demo/main.go`
- `examples/kg_ner_demo/main.go`
- `examples/kg_search_demo/main.go`
- `examples/entity_relations_demo/main.go`

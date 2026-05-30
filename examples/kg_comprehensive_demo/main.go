package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

func main() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "velocity_kg_comprehensive_")
	check(err)
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    filepath.Join(dir, "db"),
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableIndexPersistence: true,
	})
	check(err)
	defer db.Close()

	graph := db.KnowledgeGraph(kg.KGConfig{
		ChunkMaxWords: 24,
		ChunkOverlap:  6,
		IngestWorkers: 2,
		CustomNERRules: []kg.KGCustomNERRule{
			{Type: "CUSTOMER_ID", Pattern: `CUST-\d{4}`, Confidence: 0.94},
			{Type: "EVIDENCE_ID", Pattern: `EVD-\d{4}`, Confidence: 0.92},
		},
	})
	if graph == nil {
		panic("knowledge graph unavailable")
	}

	fmt.Println("=== Velocity Knowledge Graph Comprehensive Demo ===")
	fmt.Println()

	manualIngest(ctx, graph)
	connectorImports(ctx, graph, dir)
	autoIndexResources(ctx, db, graph)
	searchAndGraph(ctx, graph)
	deleteCleanup(ctx, graph)
	analytics(graph)

	fmt.Println()
	fmt.Println("done")
}

func manualIngest(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	fmt.Println("-- manual ingest with custom NER --")
	resp, err := graph.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "case-note-001.txt",
		MediaType: "text/plain",
		Title:     "Case Note 001",
		Content: []byte(strings.Join([]string{
			"CUST-1001 opened CASE-10001 after Acme Corp reported suspicious API use.",
			"Evidence EVD-7001 references invoice INV-ACME-2026 and contact analyst@example.test.",
		}, " ")),
		Metadata: map[string]string{"kind": "case_note", "owner": "investigations"},
	})
	check(err)
	fmt.Printf("manual doc=%s chunks=%d entities=%d\n", short(resp.DocID), resp.ChunkCount, resp.EntityCount)

	rules := graph.ListNERRules()
	fmt.Printf("ner rules loaded=%d\n", len(rules))
}

func connectorImports(ctx context.Context, graph *kg.KnowledgeGraphEngine, dir string) {
	fmt.Println()
	fmt.Println("-- connector imports --")

	filesDir := filepath.Join(dir, "files")
	check(os.MkdirAll(filesDir, 0755))
	check(os.WriteFile(filepath.Join(filesDir, "object-note.txt"), []byte("Object note links CUST-1001, CASE-10001, Acme Corp, and file /evidence/acme/report.pdf."), 0600))

	fileResp, err := graph.ImportConnector(ctx, kg.LocalFileConnector{Root: filesDir}, "", 10)
	check(err)
	fmt.Printf("local_file imported=%d skipped=%d\n", fileResp.Imported, fileResp.Skipped)

	csvPath := filepath.Join(dir, "customers.csv")
	check(os.WriteFile(csvPath, []byte("id,name,note\n1,Acme Corp,CUST-1001 owns contract CONTRACT-ACME-2026\n2,Globex,CASE-20002 pending review\n"), 0600))
	csvResp, err := graph.ImportConnector(ctx, kg.StructuredFileConnector{Path: csvPath, Table: "customers"}, "", 10)
	check(err)
	fmt.Printf("structured_file csv imported=%d skipped=%d\n", csvResp.Imported, csvResp.Skipped)

	staticRows := []kg.KGConnectorItem{
		{
			Source:       "static-row:cases:1",
			ResourceType: kg.ResourceSQLRow,
			ResourceID:   "cases:1",
			MediaType:    "application/json",
			Title:        "Case Row 1",
			Content:      []byte(`{"case":"CASE-10001","customer":"CUST-1001","policy":"POLICY-9000"}`),
			Metadata:     map[string]string{"table": "cases", "row": "1"},
		},
	}
	rowResp, err := graph.ImportConnector(ctx, kg.StaticRowsConnector{NameValue: "static_rows", Table: "cases", Rows: staticRows}, "", 10)
	check(err)
	fmt.Printf("static_rows imported=%d skipped=%d\n", rowResp.Imported, rowResp.Skipped)
}

func autoIndexResources(ctx context.Context, db *velocity.DB, graph *kg.KnowledgeGraphEngine) {
	fmt.Println()
	fmt.Println("-- automatic Velocity resource indexing --")

	db.EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []kg.ResourceType{kg.ResourceKV, kg.ResourceObject, kg.ResourceSecret, kg.ResourceEnvelope, kg.ResourceEntity},
		SecretValues:  false,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024 * 1024,
	})

	check(db.Put([]byte("customers/acme/profile"), []byte("Acme Corp customer profile for CUST-1001 requires SOC2 evidence.")))
	_, err := db.StoreObject("objects/acme/remediation.txt", "text/plain", "analyst", []byte("EVD-7001 report for Acme Corp CASE-10001 remediation."), nil)
	check(err)
	secret, err := db.CreateSecret(ctx, velocity.SecretRequest{Name: "acme-prod-api-key", Value: []byte("raw-secret-value-not-indexed"), Owner: "analyst"})
	check(err)
	env, err := db.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
		Label:     "Acme investigation envelope",
		Type:      velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy: "analyst",
		Payload: velocity.EnvelopePayload{
			Kind:       "note",
			InlineData: []byte("Envelope records custody for CASE-10001 and evidence EVD-7001."),
		},
	})
	check(err)
	entity, err := db.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "Acme investigation entity",
		Data:      json.RawMessage(`{"case":"CASE-10001","customer":"CUST-1001","summary":"entity indexed into KG"}`),
		CreatedBy: "analyst",
	})
	check(err)

	fmt.Printf("auto-indexed secret_version=%s envelope=%s entity=%s\n", secret.Version, short(env.EnvelopeID), short(entity.EntityID))

	resp, err := graph.Search(ctx, &kg.KGSearchRequest{Query: "raw-secret-value-not-indexed", Limit: 5})
	check(err)
	fmt.Printf("secret raw value hits=%d (expected 0 when SecretValues=false)\n", resp.TotalHits)
}

func searchAndGraph(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	fmt.Println()
	fmt.Println("-- search modes and resource graph --")

	queries := []kg.KGSearchRequest{
		{Query: `"Acme Corp"`, MatchMode: "phrase", Limit: 5},
		{Query: "CUST-1001 CASE-10001", Limit: 5},
		{Query: "CUST-100*", PrefixMatch: true, Limit: 5},
		{Query: "custmer evidnce", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 5},
	}
	for _, req := range queries {
		resp, err := graph.Search(ctx, &req)
		check(err)
		fmt.Printf("query=%q hits=%d mode=%s\n", req.Query, resp.TotalHits, resp.Mode)
		for _, hit := range resp.Hits {
			fmt.Printf("  hit source=%s title=%s entities=%d\n", hit.Source, hit.Title, len(hit.Entities))
		}
	}

	rg, err := graph.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{
		Query:     "CUST-1001 CASE-10001 Acme Corp",
		Limit:     20,
		Depth:     1,
		MinShared: 1,
	})
	check(err)
	fmt.Printf("resource_graph nodes=%d edges=%d\n", len(rg.Nodes), len(rg.Edges))
	for _, edge := range rg.Edges {
		fmt.Printf("  edge %s -> %s relation=%s confidence=%.2f evidence=%s\n",
			edge.Source, edge.Target, edge.RelationType, edge.Confidence, edge.Evidence)
	}
}

func deleteCleanup(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	fmt.Println()
	fmt.Println("-- delete cleanup --")
	resp, err := graph.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "temporary-note.txt",
		MediaType: "text/plain",
		Title:     "Temporary Note",
		Content:   []byte("Temporary KG note for CASE-90909 cleanup verification."),
	})
	check(err)
	check(graph.DeleteDocument(resp.DocID))
	_, err = graph.GetDocument(resp.DocID)
	if err != nil {
		fmt.Printf("deleted doc=%s missing_after_delete=true\n", short(resp.DocID))
		return
	}
	fmt.Printf("deleted doc=%s missing_after_delete=false\n", short(resp.DocID))
}

func analytics(graph *kg.KnowledgeGraphEngine) {
	fmt.Println()
	fmt.Println("-- analytics --")
	stats := graph.GetAnalytics()
	fmt.Printf("documents=%d chunks=%d entities=%d\n", stats.TotalDocuments, stats.TotalChunks, stats.TotalEntities)
}

func short(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:10]
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

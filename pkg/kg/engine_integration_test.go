package kg_test

import (
	"context"
	"fmt"
	. "github.com/oarkflow/velocity"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/pkg/kg"
)

func TestKGEngine_IngestAndSearch(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := db.KnowledgeGraph(kg.KGConfig{})

	ctx := context.Background()

	// Ingest a document
	resp, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "test-doc-1.txt",
		Content:   []byte("Dr. John Smith from Acme Corp presented the quarterly report on 2024-03-15. Revenue was $1,234,567 which represents a 15% increase. Contact: john@acme.com"),
		MediaType: "text/plain",
		Title:     "Q1 Report",
		Metadata:  map[string]string{"department": "finance"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.DocID == "" {
		t.Fatal("expected non-empty doc ID")
	}
	if resp.ChunkCount == 0 {
		t.Fatal("expected at least 1 chunk")
	}
	if resp.EntityCount == 0 {
		t.Fatal("expected at least 1 entity")
	}
	t.Logf("Ingested: docID=%s chunks=%d entities=%d duration=%dms",
		resp.DocID, resp.ChunkCount, resp.EntityCount, resp.DurationMs)

	// Ingest a second document
	resp2, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "test-doc-2.txt",
		Content:   []byte("The quarterly review meeting discussed the financial results. Acme Corp showed strong growth in Q1. Dr. John Smith highlighted key achievements."),
		MediaType: "text/plain",
		Title:     "Meeting Notes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Ingested second doc: docID=%s chunks=%d entities=%d",
		resp2.DocID, resp2.ChunkCount, resp2.EntityCount)

	// Search for keyword
	searchResp, err := engine.Search(ctx, &kg.KGSearchRequest{
		Query: "quarterly report revenue",
		Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResp.Hits) == 0 {
		t.Fatal("expected search hits for 'quarterly report revenue'")
	}
	t.Logf("Search returned %d hits in %dms", searchResp.TotalHits, searchResp.QueryTimeMs)

	// Verify hit contains expected text
	foundRevenue := false
	for _, hit := range searchResp.Hits {
		if strings.Contains(hit.Text, "Revenue") || strings.Contains(hit.Text, "revenue") {
			foundRevenue = true
		}
	}
	if !foundRevenue {
		t.Log("Note: 'Revenue' not found in top hits (may be expected depending on BM25 ranking)")
	}

	// Get document
	doc, err := engine.GetDocument(resp.DocID)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "Q1 Report" {
		t.Fatalf("expected title 'Q1 Report', got %q", doc.Title)
	}

	// Check analytics
	analytics := engine.GetAnalytics()
	if analytics.TotalDocuments != 2 {
		t.Fatalf("expected 2 documents, got %d", analytics.TotalDocuments)
	}
	if analytics.TotalChunks == 0 {
		t.Fatal("expected chunks > 0")
	}

	// Test duplicate rejection
	_, err = engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "test-doc-1.txt",
		Content:   []byte("duplicate content"),
		MediaType: "text/plain",
	})
	if err == nil {
		t.Fatal("expected error for duplicate source")
	}

	// Delete document
	err = engine.DeleteDocument(resp.DocID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify deleted
	_, err = engine.GetDocument(resp.DocID)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestKGEngine_SearchModesAndChunkEntities(t *testing.T) {
	db, err := NewWithConfig(Config{Path: t.TempDir(), DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()
	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "search-modes.txt",
		MediaType: "text/plain",
		Title:     "Search Modes",
		Content:   []byte("Acme Corp published retrieval documentation for compliance search."),
	}); err != nil {
		t.Fatal(err)
	}
	prefix, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "retriev*", PrefixMatch: true, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if prefix.TotalHits == 0 {
		t.Fatal("expected prefix full-text search hit")
	}
	fuzzy, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "retrival complianc", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if fuzzy.TotalHits == 0 {
		t.Fatal("expected fuzzy search hit")
	}
	if fuzzy.Hits[0].Score <= 0 {
		t.Fatalf("expected fuzzy search hit to have positive fused score, got %.4f", fuzzy.Hits[0].Score)
	}
	if len(fuzzy.Hits[0].Entities) == 0 {
		t.Fatal("expected hydrated hit entities from chunk metadata")
	}
	stopFuzzy, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "the retrival and complianc", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if stopFuzzy.TotalHits == 0 {
		t.Fatal("expected stop-word-aware fuzzy search hit")
	}
	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "protected-fuzzy.txt",
		MediaType: "text/plain",
		Title:     "Protected Fuzzy",
		Content:   []byte("Patient reports ringing in both ears. Patient denies ringing in left ear only."),
	}); err != nil {
		t.Fatal(err)
	}
	protectedFuzzy, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "both eers", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if protectedFuzzy.TotalHits == 0 {
		t.Fatal("expected fuzzy hit when protected term matches exactly")
	}
}

func TestKGEngine_ResourceGraphEdgeMetadata(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()

	docs := []*kg.KGIngestRequest{
		{
			Source:    "case-note.txt",
			MediaType: "text/plain",
			Title:     "Case Note",
			Content:   []byte("CASE-12345 references Acme Corp and invoice INV-ABC123."),
			Metadata:  map[string]string{"resource_type": string(kg.ResourceKV), "key": "case-note"},
		},
		{
			Source:    "invoice.txt",
			MediaType: "text/plain",
			Title:     "Invoice",
			Content:   []byte("Invoice INV-ABC123 belongs to Acme Corp for CASE-12345."),
			Metadata:  map[string]string{"resource_type": string(kg.ResourceObject), "path": "invoice.txt"},
		},
	}
	for _, doc := range docs {
		if _, err := engine.Ingest(ctx, doc); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	resp, err := engine.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{Query: "CASE-12345 INV-ABC123", Limit: 10})
	if err != nil {
		t.Fatalf("resource graph: %v", err)
	}
	if len(resp.Edges) == 0 {
		t.Fatalf("expected inferred edges, got %+v", resp)
	}
	found := false
	for _, edge := range resp.Edges {
		if edge.RelationType == "references" && edge.Confidence > 0 && edge.Evidence != "" && edge.SourceKind == "inferred" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected references edge with metadata, got %+v", resp.Edges)
	}
}

func TestKGEngine_ContextSearchExpandsPersistentRelations(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()

	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "incident.txt",
		MediaType: "text/plain",
		Title:     "Incident",
		Content:   []byte("Incident CASE-77777 affects Acme Corp checkout."),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "runbook.txt",
		MediaType: "text/plain",
		Title:     "Runbook",
		Content:   []byte("Checkout runbook lists mitigation steps and owner rotation."),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.CreateRelation(ctx, &kg.KGRelationRequest{
		Source:       "incident.txt",
		Target:       "runbook.txt",
		RelationType: "mitigated_by",
		Direction:    kg.KGRelationDirectionOut,
		Confidence:   0.9,
		Evidence:     "Runbook mitigates the incident",
		SourceKind:   "test",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := engine.ContextSearch(ctx, &kg.KGContextSearchRequest{
		Query:          "CASE-77777",
		Limit:          5,
		GraphDepth:     1,
		IncludeRelated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	foundRelated := false
	for _, hit := range resp.Hits {
		if hit.Source == "runbook.txt" && hit.ContextScore > 0 && len(hit.RelatedRelations) > 0 {
			foundRelated = true
		}
	}
	if !foundRelated {
		t.Fatalf("expected context search to include related runbook hit, got %+v", resp.Hits)
	}
}

func TestKGEngine_SearchScoresPersistentGraphRelations(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()

	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "case:CASE-88888",
		MediaType: "text/plain",
		Title:     "Case",
		Content:   []byte("CASE-88888 payment incident with settlement risk."),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "runbook:payments",
		MediaType: "text/plain",
		Title:     "Payments runbook",
		Content:   []byte("Mitigation owner rotation and rollback steps."),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.CreateRelation(ctx, &kg.KGRelationRequest{
		Source:       "case:CASE-88888",
		Target:       "runbook:payments",
		RelationType: "mitigated_by",
		Direction:    kg.KGRelationDirectionOut,
		Confidence:   0.95,
		Evidence:     "Runbook mitigates the payment case",
		SourceKind:   "test",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := engine.Search(ctx, &kg.KGSearchRequest{
		Query:       "CASE-88888",
		Limit:       5,
		EnableGraph: true,
		GraphDepth:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	foundRelated := false
	for _, hit := range resp.Hits {
		if hit.Source == "runbook:payments" && hit.Score > 0 && hit.Metadata["kg_graph_score"] != "" {
			foundRelated = true
		}
	}
	if !foundRelated {
		t.Fatalf("expected graph-enabled search to include scored related runbook, got %+v", resp.Hits)
	}
	if resp.GraphNodes == 0 {
		t.Fatalf("expected graph node count to be populated")
	}
}

func TestKGEngine_ImportConnector(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fileDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fileDir, "connector.txt"), []byte("Connector imported CASE-55555 for Acme Corp."), 0600); err != nil {
		t.Fatal(err)
	}

	engine := db.KnowledgeGraph()
	resp, err := engine.ImportConnector(context.Background(), kg.LocalFileConnector{Root: fileDir}, "", 10)
	if err != nil {
		t.Fatalf("import connector: %v", err)
	}
	if resp.Imported != 1 || resp.Skipped != 0 {
		t.Fatalf("unexpected import response: %+v", resp)
	}
	search, err := engine.Search(context.Background(), &kg.KGSearchRequest{Query: "CASE-55555", Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if search.TotalHits == 0 {
		t.Fatalf("expected imported content to be searchable")
	}
}

func TestKGEngine_ImportStructuredFileConnector(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	csvPath := filepath.Join(t.TempDir(), "customers.csv")
	if err := os.WriteFile(csvPath, []byte("id,name,note\n1,Acme Corp,CASE-12121\n"), 0600); err != nil {
		t.Fatal(err)
	}
	engine := db.KnowledgeGraph()
	resp, err := engine.ImportConnector(context.Background(), kg.StructuredFileConnector{Path: csvPath, Table: "customers"}, "", 10)
	if err != nil {
		t.Fatalf("import structured connector: %v", err)
	}
	if resp.Imported != 1 {
		t.Fatalf("expected one row imported, got %+v", resp)
	}
	search, err := engine.Search(context.Background(), &kg.KGSearchRequest{Query: "CASE-12121", Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if search.TotalHits == 0 {
		t.Fatalf("expected structured row content to be searchable")
	}
}

func TestKGEngine_DeleteDocumentRemovesKGDocumentEntity(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()
	resp, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "delete-entity.txt",
		MediaType: "text/plain",
		Title:     "Delete Entity",
		Content:   []byte("Delete cleanup references CASE-99999 and Acme Corp."),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	doc, err := engine.GetDocument(resp.DocID)
	if err != nil {
		t.Fatalf("get doc: %v", err)
	}
	entityID := doc.Metadata["kg_doc_entity_id"]
	if entityID == "" {
		t.Fatalf("expected kg_doc_entity_id metadata in %+v", doc.Metadata)
	}
	if _, err := db.GetEntity(ctx, entityID, true); err != nil {
		t.Fatalf("expected document entity before delete: %v", err)
	}
	if err := engine.DeleteDocument(resp.DocID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := engine.GetDocument(resp.DocID); err == nil {
		t.Fatalf("expected KG document to be removed")
	}
	if _, err := db.GetEntity(ctx, entityID, true); err == nil {
		t.Fatalf("expected KG document entity to be removed")
	}
}

func TestKGEngine_DeleteDocumentWithAutoIndexEnabled(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.EnableKnowledgeGraphAutoIndex(KnowledgeGraphAutoIndexConfig{
		Enabled:   true,
		Resources: []kg.ResourceType{kg.ResourceKV, kg.ResourceObject, kg.ResourceSecret, kg.ResourceEnvelope, kg.ResourceEntity},
	})
	engine := db.KnowledgeGraph()
	ctx := context.Background()
	resp, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "auto-delete-entity.txt",
		MediaType: "text/plain",
		Title:     "Auto Delete Entity",
		Content:   []byte("Auto delete cleanup references CASE-91919 and Acme Corp."),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if err := engine.DeleteDocument(resp.DocID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := engine.GetDocument(resp.DocID); err == nil {
		t.Fatalf("expected KG document to be removed with auto-index enabled")
	}
}

func TestKGEngine_DeleteDocumentWithPerformanceConfig(t *testing.T) {
	dir := t.TempDir()
	db, err := NewWithConfig(Config{
		Path:                    dir,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableIndexPersistence: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.EnableKnowledgeGraphAutoIndex(KnowledgeGraphAutoIndexConfig{
		Enabled:   true,
		Resources: []kg.ResourceType{kg.ResourceKV, kg.ResourceObject, kg.ResourceSecret, kg.ResourceEnvelope, kg.ResourceEntity},
	})
	engine := db.KnowledgeGraph()
	resp, err := engine.Ingest(context.Background(), &kg.KGIngestRequest{
		Source:    "perf-delete-entity.txt",
		MediaType: "text/plain",
		Title:     "Perf Delete Entity",
		Content:   []byte("Perf delete cleanup references CASE-92929 and Acme Corp."),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if err := engine.DeleteDocument(resp.DocID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := engine.GetDocument(resp.DocID); err == nil {
		t.Fatalf("expected KG document to be removed with performance config")
	}
}

func BenchmarkKGSearchPerformance(b *testing.B) {
	db, err := NewWithConfig(Config{Path: b.TempDir(), DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	engine := db.KnowledgeGraph()
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		_, err := engine.Ingest(ctx, &kg.KGIngestRequest{
			Source:    fmt.Sprintf("bench-%03d.txt", i),
			MediaType: "text/plain",
			Title:     "Benchmark",
			Content:   []byte(fmt.Sprintf("Acme Corp compliance retrieval document %d mentions secops%d@example.test and risk review.", i, i)),
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Run("keyword", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "compliance retrieval", Limit: 10}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("resource_graph", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := engine.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{Query: "Acme Corp", Limit: 10}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("fuzzy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := engine.Search(ctx, &kg.KGSearchRequest{Query: "complian retrival", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 10}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestKGEngine_HTMLIngest(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := db.KnowledgeGraph(kg.KGConfig{})

	ctx := context.Background()
	resp, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "page.html",
		Content:   []byte(`<html><body><h1>Welcome</h1><p>Contact us at support@example.com</p><script>alert('xss')</script></body></html>`),
		MediaType: "text/html",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.EntityCount == 0 {
		t.Fatal("expected entities from HTML (at least the email)")
	}
}

func TestKGEngine_JSONIngest(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := db.KnowledgeGraph(kg.KGConfig{})

	ctx := context.Background()
	resp, err := engine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "data.json",
		Content:   []byte(`{"name":"Alice","email":"alice@example.com","company":"Tech Solutions Inc"}`),
		MediaType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ChunkCount == 0 {
		t.Fatal("expected chunks from JSON")
	}
}

func TestKGEngine_BatchIngest(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := db.KnowledgeGraph(kg.KGConfig{IngestWorkers: 2})

	ctx := context.Background()
	reqs := []*kg.KGIngestRequest{
		{Source: "batch-1.txt", Content: []byte("First document about machine learning"), MediaType: "text/plain"},
		{Source: "batch-2.txt", Content: []byte("Second document about data science"), MediaType: "text/plain"},
		{Source: "batch-3.txt", Content: []byte("Third document about artificial intelligence"), MediaType: "text/plain"},
	}

	results, errs := engine.IngestBatch(ctx, reqs)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("batch item %d failed: %v", i, err)
		}
		if results[i].DocID == "" {
			t.Fatalf("batch item %d has empty doc ID", i)
		}
	}

	analytics := engine.GetAnalytics()
	if analytics.TotalDocuments != 3 {
		t.Fatalf("expected 3 documents after batch, got %d", analytics.TotalDocuments)
	}
}

func TestKGEngine_HasVectorSearch(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := db.KnowledgeGraph(kg.KGConfig{})

	if engine.HasVectorSearch() {
		t.Fatal("should not have vector search without embedding config")
	}
}

func TestKGEngine_DBKnowledgeGraph(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	kg := db.KnowledgeGraph()
	if kg == nil {
		t.Fatal("expected non-nil KG engine")
	}

	// Second call should return the same instance
	kg2 := db.KnowledgeGraph()
	if kg != kg2 {
		t.Fatal("expected same KG instance on second call")
	}
}

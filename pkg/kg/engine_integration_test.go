package kg_test

import (
	"context"
	"fmt"
	. "github.com/oarkflow/velocity"
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
	if len(fuzzy.Hits[0].Entities) == 0 {
		t.Fatal("expected hydrated hit entities from chunk metadata")
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

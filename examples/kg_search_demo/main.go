package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
)

func main() {
	path := "./kg_demo_db"
	_ = os.RemoveAll(path)

	db, err := velocity.NewWithConfig(velocity.Config{Path: path})
	if err != nil {
		panic(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(path)
	}()

	// Initialize the Knowledge Graph engine (BM25-only mode, no embedding endpoint)
	kg := db.KnowledgeGraph(velocity.KGConfig{
		ChunkMaxWords: 128,
		ChunkOverlap:  32,
		IngestWorkers: 4,
	})
	if kg == nil {
		panic("failed to create KG engine")
	}

	fmt.Println("=== Knowledge Graph Engine Demo ===")
	fmt.Println()

	ctx := context.Background()

	// --- Ingest Documents ---
	fmt.Println("--- Ingesting Documents ---")

	docs := []velocity.KGIngestRequest{
		{
			Source:    "annual-report-2024.txt",
			MediaType: "text/plain",
			Title:     "Annual Report 2024",
			Content: []byte(`Acme Corp reported record revenue of $2.4 billion for fiscal year 2024,
representing a 23% increase year-over-year. CEO Dr. Jane Wilson credited the growth to
expansion into European markets, particularly in Germany and France. The company's
cloud services division, led by VP of Engineering Mr. Robert Chen, grew 45% and now
accounts for 60% of total revenue. Acme Corp plans to invest $500 million in AI research
during 2025. Contact: investors@acmecorp.com or call (555) 123-4567.`),
			Metadata: map[string]string{"department": "finance", "year": "2024"},
		},
		{
			Source:    "partnership-announcement.txt",
			MediaType: "text/plain",
			Title:     "Strategic Partnership",
			Content: []byte(`Acme Corp announced a strategic partnership with Global Systems Inc on
March 15, 2024. The partnership focuses on developing next-generation cloud infrastructure.
Dr. Jane Wilson and Global Systems CEO Mr. David Park signed the agreement at the
World Technology Summit in Berlin. The deal is valued at approximately $150 million over
three years. Both companies will establish a joint research lab in Munich, Germany.
Press contact: press@acmecorp.com`),
			Metadata: map[string]string{"department": "pr", "type": "announcement"},
		},
		{
			Source:    "product-launch.html",
			MediaType: "text/html",
			Title:     "Product Launch",
			Content: []byte(`<html><body>
<h1>Acme Cloud Platform v3.0 Launch</h1>
<p>Acme Corp is proud to announce the launch of <strong>Acme Cloud Platform v3.0</strong>,
featuring AI-powered analytics and real-time data processing capabilities.</p>
<p>Key features include:</p>
<ul>
<li>Real-time stream processing at 1M events/second</li>
<li>Built-in machine learning pipelines</li>
<li>99.99% uptime SLA</li>
</ul>
<p>Mr. Robert Chen, VP of Engineering, stated: "This release represents two years of
intensive development. We're delivering 10x performance improvements over v2.0."</p>
<p>Pricing starts at $99/month. Visit <a href="https://acmecorp.com/cloud">https://acmecorp.com/cloud</a>
for more information.</p>
<script>console.log('tracking');</script>
</body></html>`),
			Metadata: map[string]string{"department": "product", "version": "3.0"},
		},
		{
			Source:    "team-data.json",
			MediaType: "application/json",
			Title:     "Engineering Team",
			Content: []byte(`{
				"team": "Cloud Infrastructure",
				"lead": "Robert Chen",
				"email": "rchen@acmecorp.com",
				"members": [
					{"name": "Alice Johnson", "role": "Senior Engineer", "focus": "distributed systems"},
					{"name": "Bob Martinez", "role": "Staff Engineer", "focus": "machine learning"},
					{"name": "Carol Williams", "role": "Engineer", "focus": "data pipelines"}
				],
				"location": "San Francisco",
				"budget": "$12,000,000"
			}`),
			Metadata: map[string]string{"department": "engineering"},
		},
	}

	for _, doc := range docs {
		resp, err := kg.Ingest(ctx, &doc)
		if err != nil {
			fmt.Printf("  ERROR ingesting %s: %v\n", doc.Source, err)
			continue
		}
		fmt.Printf("  Ingested: %-35s → docID=%s chunks=%d entities=%d (%dms)\n",
			doc.Source, resp.DocID[:12]+"...", resp.ChunkCount, resp.EntityCount, resp.DurationMs)
	}
	fmt.Println()

	// --- Search Examples ---
	fmt.Println("--- Search Examples ---")
	fmt.Println()

	queries := []struct {
		name  string
		query string
		limit int
	}{
		{"Revenue and financial results", "revenue growth", 5},
		{"Cloud platform and engineering", "cloud platform engineering", 5},
		{"Partnership and collaboration", "partnership agreement strategic", 5},
		{"People and leadership", "CEO VP engineering", 5},
		{"AI and machine learning", "AI machine learning research", 5},
	}

	for _, q := range queries {
		fmt.Printf("  Query: %q\n", q.query)
		resp, err := kg.Search(ctx, &velocity.KGSearchRequest{
			Query: q.query,
			Limit: q.limit,
		})
		if err != nil {
			fmt.Printf("    ERROR: %v\n", err)
			continue
		}
		fmt.Printf("    Results: %d hits in %dms (mode: %s)\n", resp.TotalHits, resp.QueryTimeMs, resp.Mode)
		for i, hit := range resp.Hits {
			text := hit.Text
			if len(text) > 100 {
				text = text[:100] + "..."
			}
			fmt.Printf("    [%d] score=%.6f source=%s\n", i+1, hit.Score, hit.Source)
			fmt.Printf("        %s\n", text)
		}
		fmt.Println()
	}

	// --- Get Document ---
	fmt.Println("--- Document Retrieval ---")
	resp, _ := kg.Ingest(ctx, &velocity.KGIngestRequest{
		Source:    "test-retrieval.txt",
		Content:   []byte("This is a test document for retrieval demonstration."),
		MediaType: "text/plain",
		Title:     "Test Document",
	})
	if resp != nil {
		doc, err := kg.GetDocument(resp.DocID)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
		} else {
			fmt.Printf("  Retrieved document: ID=%s Title=%q Source=%s\n", doc.ID[:12]+"...", doc.Title, doc.Source)
			fmt.Printf("  Chunks: %d  Entities: %d  Ingested: %s\n", doc.ChunkCount, doc.EntityCount, doc.IngestedAt.Format("2006-01-02 15:04:05"))
		}
	}
	fmt.Println()

	// --- Analytics ---
	fmt.Println("--- Corpus Analytics ---")
	analytics := kg.GetAnalytics()
	fmt.Printf("  Total documents: %d\n", analytics.TotalDocuments)
	fmt.Printf("  Total chunks:    %d\n", analytics.TotalChunks)
	fmt.Printf("  Total entities:  %d\n", analytics.TotalEntities)
	fmt.Println()

	// --- Metadata Filtering ---
	fmt.Println("--- Search with Metadata Filters ---")
	filteredResp, err := kg.Search(ctx, &velocity.KGSearchRequest{
		Query:   "cloud",
		Limit:   5,
		Filters: map[string]string{"department": "product"},
	})
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Query: 'cloud' filtered by department=product\n")
		fmt.Printf("  Results: %d hits\n", filteredResp.TotalHits)
		for _, hit := range filteredResp.Hits {
			fmt.Printf("    source=%s department=%s\n", hit.Source, hit.Metadata["department"])
		}
	}
	fmt.Println()

	// --- Delete Document ---
	fmt.Println("--- Delete Document ---")
	if resp != nil {
		err = kg.DeleteDocument(resp.DocID)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
		} else {
			fmt.Printf("  Deleted document: %s\n", resp.DocID[:12]+"...")
		}
		_, err = kg.GetDocument(resp.DocID)
		if err != nil {
			fmt.Printf("  Verified: document no longer exists\n")
		}
	}
	fmt.Println()

	// --- Vector Search Info ---
	fmt.Println("--- Vector Search Status ---")
	if kg.HasVectorSearch() {
		fmt.Println("  Vector search: ENABLED")
	} else {
		fmt.Println("  Vector search: DISABLED (no embedding endpoint configured)")
		fmt.Println("  To enable, pass KGConfig with EmbeddingEndpoint, EmbeddingModel, EmbeddingDim")
		fmt.Println("  Example: KGConfig{EmbeddingEndpoint: \"http://localhost:11434/api/embeddings\", EmbeddingDim: 768}")
	}

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
}

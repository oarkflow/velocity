//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	path := "./kg_batch_demo_db"
	_ = os.RemoveAll(path)

	db, err := velocity.NewWithConfig(velocity.Config{Path: path})
	if err != nil {
		panic(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(path)
	}()

	kg := db.KnowledgeGraph(velocity.KGConfig{
		ChunkMaxWords: 64,
		ChunkOverlap:  16,
		IngestWorkers: 8,
	})
	if kg == nil {
		panic("failed to create KG engine")
	}

	fmt.Println("=== Knowledge Graph Batch Ingest & Search Benchmark ===")
	fmt.Println()

	ctx := context.Background()

	// Generate synthetic documents
	topics := []string{
		"machine learning", "distributed systems", "cloud computing",
		"database optimization", "network security", "data pipelines",
		"microservices architecture", "container orchestration",
		"real-time analytics", "natural language processing",
	}

	companies := []string{
		"Acme Corp", "Global Systems Inc", "Tech Solutions Ltd",
		"DataFlow Corp", "CloudScale Inc",
	}

	people := []string{
		"Dr. Alice Johnson", "Mr. Bob Martinez", "Mrs. Carol Williams",
		"Dr. David Park", "Ms. Emily Chen",
	}

	numDocs := 100
	fmt.Printf("Generating %d synthetic documents...\n", numDocs)

	var reqs []*velocity.KGIngestRequest
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < numDocs; i++ {
		topic1 := topics[rng.Intn(len(topics))]
		topic2 := topics[rng.Intn(len(topics))]
		company := companies[rng.Intn(len(companies))]
		person := people[rng.Intn(len(people))]

		content := fmt.Sprintf(
			"%s recently published a report on %s and %s. "+
				"%s led the research team that developed new approaches to %s. "+
				"The project budget was $%d,000 and ran from January 2024 to March 2024. "+
				"For more information, contact research@%s.com or visit https://%s.com/research. "+
				"The team achieved a %d%% improvement in performance metrics. "+
				"Key findings were presented at the 2024 International Conference on %s. "+
				"The paper can be downloaded from https://arxiv.org/abs/2024.%05d",
			company, topic1, topic2,
			person, topic1,
			rng.Intn(900)+100,
			sanitize(company), sanitize(company),
			rng.Intn(50)+10,
			topic1,
			rng.Intn(99999),
		)

		reqs = append(reqs, &velocity.KGIngestRequest{
			Source:    fmt.Sprintf("doc-%04d.txt", i),
			Content:   []byte(content),
			MediaType: "text/plain",
			Title:     fmt.Sprintf("Report: %s at %s", topic1, company),
			Metadata: map[string]string{
				"topic":   topic1,
				"company": company,
			},
		})
	}

	// Batch ingest
	fmt.Printf("Batch ingesting %d documents with %d workers...\n", numDocs, 8)
	start := time.Now()

	results, errs := kg.IngestBatch(ctx, reqs)

	ingestDuration := time.Since(start)
	successCount := 0
	totalChunks := 0
	totalEntities := 0
	for i, err := range errs {
		if err != nil {
			fmt.Printf("  Doc %d error: %v\n", i, err)
		} else {
			successCount++
			totalChunks += results[i].ChunkCount
			totalEntities += results[i].EntityCount
		}
	}

	fmt.Printf("\nIngest Results:\n")
	fmt.Printf("  Documents ingested: %d/%d\n", successCount, numDocs)
	fmt.Printf("  Total chunks:       %d\n", totalChunks)
	fmt.Printf("  Total entities:     %d\n", totalEntities)
	fmt.Printf("  Total time:         %v\n", ingestDuration)
	fmt.Printf("  Throughput:         %.0f docs/sec\n", float64(successCount)/ingestDuration.Seconds())
	fmt.Printf("  Avg per doc:        %v\n", ingestDuration/time.Duration(successCount))
	fmt.Println()

	// Search benchmark
	fmt.Println("--- Search Benchmark ---")
	searchQueries := []string{
		"machine learning performance improvement",
		"cloud computing infrastructure",
		"database optimization distributed systems",
		"security network architecture",
		"real-time analytics data pipelines",
	}

	for _, query := range searchQueries {
		start := time.Now()
		resp, err := kg.Search(ctx, &velocity.KGSearchRequest{
			Query: query,
			Limit: 10,
		})
		searchDuration := time.Since(start)

		if err != nil {
			fmt.Printf("  Query %q: ERROR %v\n", query, err)
			continue
		}
		fmt.Printf("  Query: %-50s → %2d hits in %v\n", fmt.Sprintf("%q", query), resp.TotalHits, searchDuration)
	}
	fmt.Println()

	// Analytics
	fmt.Println("--- Final Analytics ---")
	analytics := kg.GetAnalytics()
	fmt.Printf("  Documents: %d\n", analytics.TotalDocuments)
	fmt.Printf("  Chunks:    %d\n", analytics.TotalChunks)
	fmt.Printf("  Entities:  %d\n", analytics.TotalEntities)

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
}

func sanitize(s string) string {
	result := make([]byte, 0, len(s))
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			if c >= 'A' && c <= 'Z' {
				c = c + 32 // toLower
			}
			result = append(result, byte(c))
		}
	}
	return string(result)
}

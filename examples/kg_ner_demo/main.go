package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
)

func main() {
	path := "./kg_ner_demo_db"
	_ = os.RemoveAll(path)

	db, err := velocity.NewWithConfig(velocity.Config{Path: path})
	if err != nil {
		panic(err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(path)
	}()

	fmt.Println("=== Named Entity Recognition (NER) Demo ===")
	fmt.Println()

	// Use the NER engine directly
	ner := velocity.NewRuleBasedNER()

	// --- Built-in entity types ---
	samples := []struct {
		name string
		text string
	}{
		{
			"Business Report",
			`Acme Corp reported $2.4 billion in revenue for 2024. CEO Dr. Jane Wilson
announced the results on 2024-03-15. The stock rose 12% in after-hours trading.
Contact: investors@acmecorp.com or (555) 123-4567. Visit https://acmecorp.com/ir
for the full report. Competitor Global Systems Inc posted $1.8 billion.`,
		},
		{
			"Technical Document",
			`The server at 192.168.1.100 experienced a security breach on 01/15/2024.
Mr. Robert Chen from the security team investigated. The attacker used credit card
4111-1111-1111-1111 in a test transaction. SSN 123-45-6789 was exposed.
Total damages estimated at $500,000 USD. Report filed with Tech Solutions Ltd.`,
		},
		{
			"Meeting Notes",
			`Meeting between Dr. Alice Johnson and Mrs. Carol Williams on March 20, 2024.
Topics discussed: Q1 budget of $12,000,000 for cloud infrastructure.
DataFlow Corp partnership valued at 250 EUR. Project completion at 85%.
Action items sent to alice@company.com and carol@company.com.
Next meeting scheduled for 2024-04-01.`,
		},
	}

	for _, sample := range samples {
		fmt.Printf("--- %s ---\n", sample.name)
		entities := ner.Extract(sample.text)

		// Group by type
		byType := make(map[string][]velocity.KGEntity)
		for _, e := range entities {
			byType[e.Type] = append(byType[e.Type], e)
		}

		types := []string{"PERSON", "ORG", "EMAIL", "URL", "PHONE", "DATE", "MONEY", "PERCENTAGE", "IP_ADDRESS", "SSN", "CREDIT_CARD"}
		for _, t := range types {
			ents, ok := byType[t]
			if !ok {
				continue
			}
			fmt.Printf("  %-12s ", t)
			for i, e := range ents {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s (%.0f%%)", e.Surface, e.Confidence*100)
			}
			fmt.Println()
		}
		fmt.Printf("  Total: %d entities found\n", len(entities))
		fmt.Println()
	}

	// --- Custom Rules ---
	fmt.Println("--- Custom NER Rules ---")

	// Add custom rules
	ner.AddRule("TICKET", `[A-Z]+-\d+`, 0.90)
	ner.AddRule("VERSION", `v\d+\.\d+(?:\.\d+)?`, 0.85)
	ner.AddRule("SHA", `[0-9a-f]{7,40}`, 0.70)

	devText := `Fix JIRA-1234: upgrade to v3.2.1 from v2.0. See also BUG-5678.
Commit abc1234 merged by Dr. Alice Johnson on 2024-03-20. Deploy to 10.0.0.5.`

	fmt.Printf("  Text: %s\n", devText)
	entities := ner.Extract(devText)

	byType := make(map[string][]velocity.KGEntity)
	for _, e := range entities {
		byType[e.Type] = append(byType[e.Type], e)
	}
	for t, ents := range byType {
		fmt.Printf("  %-12s ", t)
		for i, e := range ents {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s", e.Surface)
		}
		fmt.Println()
	}
	fmt.Println()

	// --- Full Pipeline with NER ---
	fmt.Println("--- NER in Full Pipeline ---")

	kg := db.KnowledgeGraph(velocity.KGConfig{})
	ctx := context.Background()

	resp, err := kg.Ingest(ctx, &velocity.KGIngestRequest{
		Source:    "ner-test.txt",
		Content:   []byte(samples[0].text),
		MediaType: "text/plain",
		Title:     "NER Test Document",
	})
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Ingested: %d entities auto-extracted and indexed as graph nodes\n", resp.EntityCount)
		fmt.Printf("  Doc ID: %s\n", resp.DocID)

		analytics := kg.GetAnalytics()
		fmt.Printf("  Total entities in corpus: %d\n", analytics.TotalEntities)
	}

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
}

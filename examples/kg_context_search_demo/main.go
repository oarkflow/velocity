package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

func main() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "velocity_kg_context_")
	check(err)
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    dir,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableIndexPersistence: true,
	})
	check(err)
	defer db.Close()

	graph := db.KnowledgeGraph(kg.KGConfig{
		ChunkMaxWords: 64,
		ChunkOverlap:  8,
	})

	applyOntology(ctx, graph)
	ingestDocuments(ctx, graph)
	createRelations(ctx, graph)

	resp, err := graph.ContextSearch(ctx, &kg.KGContextSearchRequest{
		Query:          "CASE-77777",
		Limit:          10,
		GraphDepth:     2,
		RelationTypes:  []string{"mitigated_by", "depends_on", "owned_by"},
		IncludeRelated: true,
		ContextWeight:  0.45,
	})
	check(err)

	fmt.Println("Context search: CASE-77777")
	for i, hit := range resp.Hits {
		fmt.Printf("%d. %-12s source=%-20s final=%.4f base=%.4f context=%.4f relations=%d\n",
			i+1, hit.MatchKind, hit.Source, hit.FinalScore, hit.BaseScore, hit.ContextScore, len(hit.RelatedRelations))
		if hit.Title != "" {
			fmt.Printf("   title=%s\n", hit.Title)
		}
		for _, rel := range hit.RelatedRelations {
			fmt.Printf("   via %s: %s -> %s confidence=%.2f\n", rel.RelationType, rel.Source, rel.Target, rel.Confidence)
		}
	}
}

func applyOntology(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	_, err := graph.CreateOntology(ctx, &kg.KGOntology{
		Name:    "default",
		Version: "ops-demo-v1",
		Taxonomies: map[string]kg.KGOntologyTaxonomy{
			"resource": {
				Name: "resource",
				Terms: map[string]kg.KGOntologyTaxonomyTerm{
					"resource": {ID: "resource", Label: "Resource"},
					"case":     {ID: "case", Label: "Case", Parent: "resource", Synonyms: []string{"incident", "ticket"}},
					"runbook":  {ID: "runbook", Label: "Runbook", Parent: "resource"},
					"service":  {ID: "service", Label: "Service", Parent: "resource"},
					"team":     {ID: "team", Label: "Team", Parent: "resource"},
				},
			},
		},
		NodeTypes: map[string]kg.KGOntologyNodeType{
			"case":    {Type: "case", ParentTypes: []string{"resource"}},
			"runbook": {Type: "runbook", ParentTypes: []string{"resource"}},
			"service": {Type: "service", ParentTypes: []string{"resource"}},
			"team":    {Type: "team", ParentTypes: []string{"resource"}},
		},
		RelationTypes: map[string]kg.KGOntologyRelationType{
			"mitigated_by": {
				Type:           "mitigated_by",
				ParentTypes:    []string{"operational_link"},
				AllowedSources: []string{"case"},
				AllowedTargets: []string{"runbook"},
				Direction:      kg.KGRelationDirectionOut,
				RequiredFields: []string{"evidence", "source_kind"},
			},
			"depends_on": {
				Type:           "depends_on",
				ParentTypes:    []string{"dependency"},
				AllowedSources: []string{"runbook", "service"},
				AllowedTargets: []string{"service"},
				Direction:      kg.KGRelationDirectionOut,
			},
			"owned_by": {
				Type:           "owned_by",
				ParentTypes:    []string{"ownership"},
				AllowedSources: []string{"service"},
				AllowedTargets: []string{"team"},
				Direction:      kg.KGRelationDirectionOut,
			},
		},
	})
	check(err)
}

func ingestDocuments(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	docs := []*kg.KGIngestRequest{
		{
			Source:    "case:CASE-77777",
			MediaType: "text/plain",
			Title:     "Checkout Incident",
			Content:   []byte("Incident CASE-77777 reports checkout latency for Acme Corp customers."),
			Metadata:  map[string]string{"domain": "ops", "resource_type": "case"},
		},
		{
			Source:    "runbook:checkout-latency",
			MediaType: "text/plain",
			Title:     "Checkout Latency Runbook",
			Content:   []byte("Runbook for checkout latency mitigation: inspect queue depth, cache health, and payment service retries."),
			Metadata:  map[string]string{"domain": "ops", "resource_type": "runbook"},
		},
		{
			Source:    "service:payment-api",
			MediaType: "text/plain",
			Title:     "Payment API",
			Content:   []byte("Payment API handles authorization retries and checkout payment callbacks."),
			Metadata:  map[string]string{"domain": "ops", "resource_type": "service"},
		},
		{
			Source:    "team:payments",
			MediaType: "text/plain",
			Title:     "Payments Team",
			Content:   []byte("Payments team owns payment service operations, retry policy, and incident escalation."),
			Metadata:  map[string]string{"domain": "ops", "resource_type": "team"},
		},
	}
	for _, doc := range docs {
		_, err := graph.Ingest(ctx, doc)
		check(err)
	}
}

func createRelations(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	relations := []*kg.KGRelationRequest{
		{
			Source:       "case:CASE-77777",
			Target:       "runbook:checkout-latency",
			RelationType: "mitigated_by",
			Direction:    kg.KGRelationDirectionOut,
			Confidence:   0.95,
			Evidence:     "Runbook is linked from the incident mitigation checklist.",
			SourceKind:   "operator",
			CreatedBy:    "demo",
		},
		{
			Source:       "runbook:checkout-latency",
			Target:       "service:payment-api",
			RelationType: "depends_on",
			Direction:    kg.KGRelationDirectionOut,
			Confidence:   0.85,
			Evidence:     "Runbook instructs operators to inspect payment API retries.",
			SourceKind:   "operator",
			CreatedBy:    "demo",
		},
		{
			Source:       "service:payment-api",
			Target:       "team:payments",
			RelationType: "owned_by",
			Direction:    kg.KGRelationDirectionOut,
			Confidence:   0.90,
			Evidence:     "Service catalog ownership record.",
			SourceKind:   "catalog",
			CreatedBy:    "demo",
		},
	}
	for _, rel := range relations {
		_, err := graph.CreateRelation(ctx, rel)
		check(err)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

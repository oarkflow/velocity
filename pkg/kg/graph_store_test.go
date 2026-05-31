package kg

import (
	"context"
	"testing"
)

func TestPersistentRelationsCRUDAndQuery(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}

	rel, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:api",
		Target:       "table:customers",
		RelationType: "depends_on",
		Confidence:   0.91,
		Evidence:     "api reads customers table",
		SourceKind:   "test",
		CreatedBy:    "unit",
		Attributes:   map[string]string{"criticality": "high"},
	})
	if err != nil {
		t.Fatalf("create relation: %v", err)
	}
	if rel.RelationID == "" || rel.Status != KGRelationStatusActive || rel.Revision != 1 {
		t.Fatalf("unexpected created relation: %+v", rel)
	}

	got, err := engine.GetRelation(ctx, rel.RelationID)
	if err != nil {
		t.Fatalf("get relation: %v", err)
	}
	if got.Source != "service:api" || got.Target != "table:customers" {
		t.Fatalf("unexpected relation endpoints: %+v", got)
	}

	nextConfidence := 0.95
	updated, err := engine.UpdateRelation(ctx, rel.RelationID, &KGRelationUpdate{Confidence: &nextConfidence, UpdatedBy: "unit"})
	if err != nil {
		t.Fatalf("update relation: %v", err)
	}
	if updated.Confidence != nextConfidence || updated.Revision != 2 {
		t.Fatalf("unexpected updated relation: %+v", updated)
	}

	results, err := engine.QueryRelations(ctx, &KGRelationQuery{
		Source:        "service:api",
		RelationTypes: []string{"depends_on"},
		MinConfidence: 0.9,
	})
	if err != nil {
		t.Fatalf("query relations: %v", err)
	}
	if len(results) != 1 || results[0].RelationID != rel.RelationID {
		t.Fatalf("unexpected query results: %+v", results)
	}

	if err := engine.DeleteRelation(ctx, rel.RelationID, "unit"); err != nil {
		t.Fatalf("delete relation: %v", err)
	}
	results, err = engine.QueryRelations(ctx, &KGRelationQuery{Source: "service:api"})
	if err != nil {
		t.Fatalf("query after delete: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("deleted relation should be hidden by default: %+v", results)
	}
	results, err = engine.QueryRelations(ctx, &KGRelationQuery{Source: "service:api", IncludeDeleted: true})
	if err != nil {
		t.Fatalf("query deleted relation: %v", err)
	}
	if len(results) != 1 || results[0].Status != KGRelationStatusDeleted {
		t.Fatalf("expected deleted tombstone: %+v", results)
	}
}

func TestOntologyValidationRejectsInvalidRelations(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}

	_, err = engine.CreateOntology(ctx, &KGOntology{
		Name:    "default",
		Version: "test",
		RelationTypes: map[string]KGOntologyRelationType{
			"owns": {
				Type:                 "owns",
				AllowedSources:       []string{"person"},
				AllowedTargets:       []string{"account"},
				Direction:            KGRelationDirectionOut,
				RequiredFields:       []string{"evidence"},
				MaxOutgoingPerSource: 1,
			},
		},
	})
	if err != nil {
		t.Fatalf("create ontology: %v", err)
	}

	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:billing",
		Target:       "account:123",
		RelationType: "owns",
		Evidence:     "wrong source type",
	}); err == nil {
		t.Fatalf("expected source type rejection")
	}
	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "person:alice",
		Target:       "account:123",
		RelationType: "owns",
	}); err == nil {
		t.Fatalf("expected evidence rejection")
	}
	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "person:alice",
		Target:       "account:123",
		RelationType: "owns",
		Evidence:     "bank KYC record",
	}); err != nil {
		t.Fatalf("valid relation rejected: %v", err)
	}
	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "person:alice",
		Target:       "account:456",
		RelationType: "owns",
		Evidence:     "second KYC record",
	}); err == nil {
		t.Fatalf("expected outgoing cardinality rejection")
	}
}

func TestGraphQueryPathMetricsAndComponents(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	for _, rel := range []KGRelationRequest{
		{Source: "service:api", Target: "service:worker", RelationType: "calls", Confidence: 0.9},
		{Source: "service:worker", Target: "queue:jobs", RelationType: "uses", Confidence: 0.8},
		{Source: "queue:jobs", Target: "table:events", RelationType: "writes", Confidence: 0.85},
		{Source: "service:billing", Target: "table:invoices", RelationType: "writes", Confidence: 0.95},
	} {
		if _, err := engine.CreateRelation(ctx, &rel); err != nil {
			t.Fatalf("create relation %+v: %v", rel, err)
		}
	}

	graph, err := engine.QueryGraph(ctx, &KGGraphQuery{SeedIDs: []string{"service:api"}, Depth: 3})
	if err != nil {
		t.Fatalf("query graph: %v", err)
	}
	if len(graph.Relations) != 3 || len(graph.Nodes) != 4 {
		t.Fatalf("unexpected graph response: nodes=%d relations=%d", len(graph.Nodes), len(graph.Relations))
	}

	path, err := engine.ShortestPath(ctx, "service:api", "table:events", &KGGraphQuery{Depth: 4})
	if err != nil {
		t.Fatalf("shortest path: %v", err)
	}
	if len(path.Nodes) != 4 || path.Nodes[0] != "service:api" || path.Nodes[3] != "table:events" {
		t.Fatalf("unexpected path: %+v", path)
	}

	metrics, err := engine.GraphMetrics(ctx, nil)
	if err != nil {
		t.Fatalf("graph metrics: %v", err)
	}
	if metrics.NodeCount != 6 || metrics.RelationCount != 4 || metrics.OutDegreeByNode["service:api"] != 1 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}

	components, err := engine.ConnectedComponents(ctx, nil)
	if err != nil {
		t.Fatalf("connected components: %v", err)
	}
	if len(components) != 2 || len(components[0]) != 4 || len(components[1]) != 2 {
		t.Fatalf("unexpected components: %+v", components)
	}
}

func TestEntityMergeAliasResolveAndSplit(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}

	proposal, err := engine.ProposeMerge(ctx, &KGEntityMergeRequest{
		SourceIDs: []string{"person:alice-old", "person:a.smith"},
		TargetID:  "person:alice",
		Reason:    "same employee id",
		CreatedBy: "reviewer",
	})
	if err != nil {
		t.Fatalf("propose merge: %v", err)
	}
	if proposal.Status != KGMergeStatusPending {
		t.Fatalf("unexpected proposal: %+v", proposal)
	}

	approved, err := engine.ApproveMerge(ctx, proposal.ProposalID, "approver")
	if err != nil {
		t.Fatalf("approve merge: %v", err)
	}
	if approved.Status != KGMergeStatusApproved {
		t.Fatalf("unexpected approved proposal: %+v", approved)
	}

	canonical, chain, err := engine.ResolveEntity(ctx, "person:alice-old")
	if err != nil {
		t.Fatalf("resolve entity: %v", err)
	}
	if canonical != "person:alice" || len(chain) != 1 {
		t.Fatalf("unexpected alias resolution canonical=%s chain=%+v", canonical, chain)
	}

	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "person:alice-old",
		Target:       "account:123",
		RelationType: "owns",
		Evidence:     "profile record",
	}); err != nil {
		t.Fatalf("create relation with alias source: %v", err)
	}
	relations, err := engine.QueryRelations(ctx, &KGRelationQuery{Source: "person:alice"})
	if err != nil {
		t.Fatalf("query canonical relation: %v", err)
	}
	if len(relations) != 1 || relations[0].Source != "person:alice" {
		t.Fatalf("relation should be canonicalized: %+v", relations)
	}

	if err := engine.SplitEntity(ctx, []string{"person:alice-old"}, "approver"); err != nil {
		t.Fatalf("split entity: %v", err)
	}
	canonical, chain, err = engine.ResolveEntity(ctx, "person:alice-old")
	if err != nil {
		t.Fatalf("resolve after split: %v", err)
	}
	if canonical != "person:alice-old" || len(chain) != 0 {
		t.Fatalf("split should remove alias canonical=%s chain=%+v", canonical, chain)
	}
}

func TestAuthzFilterAppliesToRelationsAndGraph(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{
		AuthzFilter: func(ctx context.Context, resource KGAuthzResource) bool {
			return resource.Source != "service:secret" && resource.Target != "service:secret"
		},
	})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}

	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:api",
		Target:       "table:public",
		RelationType: "reads",
	}); err != nil {
		t.Fatalf("create public relation: %v", err)
	}
	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:secret",
		Target:       "table:hidden",
		RelationType: "reads",
	}); err == nil {
		t.Fatalf("expected authz filter to reject secret relation creation")
	}

	raw := NewKGGraphStore(engine.db)
	if _, err := raw.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:secret",
		Target:       "table:hidden",
		RelationType: "reads",
	}); err != nil {
		t.Fatalf("seed hidden relation: %v", err)
	}

	relations, err := engine.QueryRelations(ctx, nil)
	if err != nil {
		t.Fatalf("query relations: %v", err)
	}
	if len(relations) != 1 || relations[0].Source == "service:secret" {
		t.Fatalf("authz should filter hidden relations: %+v", relations)
	}

	graph, err := engine.QueryGraph(ctx, &KGGraphQuery{Depth: 1})
	if err != nil {
		t.Fatalf("query graph: %v", err)
	}
	if len(graph.Relations) != 1 {
		t.Fatalf("authz should filter graph relations: %+v", graph.Relations)
	}
}

func TestMutationLogAndRebuildHook(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	if _, err := engine.CreateRelation(ctx, &KGRelationRequest{
		Source:       "service:api",
		Target:       "table:events",
		RelationType: "writes",
		CreatedBy:    "unit",
	}); err != nil {
		t.Fatalf("create relation: %v", err)
	}
	records, err := engine.ListMutationLog(ctx, 10)
	if err != nil {
		t.Fatalf("list mutation log: %v", err)
	}
	if len(records) == 0 || records[len(records)-1].Action != "create" {
		t.Fatalf("unexpected mutation records: %+v", records)
	}
	if err := engine.RebuildIndexes(ctx); err != nil {
		t.Fatalf("rebuild indexes: %v", err)
	}
}

func TestMaterializeResourceGraphPersistsInferredRelations(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	docs := []*KGIngestRequest{
		{
			Source:    "case-note",
			MediaType: "text/plain",
			Content:   []byte("CASE-12345 references Acme Corp remediation."),
			Metadata:  map[string]string{"resource_type": string(ResourceKV), "key": "case-note"},
		},
		{
			Source:    "object-note",
			MediaType: "text/plain",
			Content:   []byte("Acme Corp evidence for CASE-12345."),
			Metadata:  map[string]string{"resource_type": string(ResourceObject), "path": "object-note"},
		},
	}
	for _, doc := range docs {
		if _, err := engine.Ingest(ctx, doc); err != nil {
			t.Fatalf("ingest %s: %v", doc.Source, err)
		}
	}

	resp, err := engine.MaterializeResourceGraph(ctx, &KGMaterializeRelationsRequest{
		ResourceGraph: KGResourceGraphRequest{Query: "CASE-12345 Acme", Limit: 10},
		CreatedBy:     "unit",
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if resp.Created == 0 || len(resp.Relations) == 0 {
		t.Fatalf("expected materialized relations: %+v", resp)
	}
	relations, err := engine.QueryRelations(ctx, &KGRelationQuery{SourceKind: "inferred"})
	if err != nil {
		t.Fatalf("query inferred relations: %v", err)
	}
	if len(relations) != resp.Created || relations[0].Metadata["materialized_from"] != "resource_graph" {
		t.Fatalf("unexpected persisted relations: %+v", relations)
	}

	again, err := engine.MaterializeResourceGraph(ctx, &KGMaterializeRelationsRequest{
		ResourceGraph: KGResourceGraphRequest{Query: "CASE-12345 Acme", Limit: 10},
		CreatedBy:     "unit",
	})
	if err != nil {
		t.Fatalf("materialize again: %v", err)
	}
	if again.Created != 0 || again.Skipped == 0 {
		t.Fatalf("expected idempotent skipped relations: %+v", again)
	}

	graph, err := engine.QueryGraph(ctx, &KGGraphQuery{SeedSearch: "CASE-12345", Depth: 1})
	if err != nil {
		t.Fatalf("query graph from search seed: %v", err)
	}
	if len(graph.Relations) == 0 {
		t.Fatalf("expected search-seeded graph traversal to find materialized relations")
	}
}

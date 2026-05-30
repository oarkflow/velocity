#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/velocity-kg-demo.XXXXXX")}"

cleanup() {
  if [[ "${KEEP_KG_DEMO:-}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  else
    echo "Keeping KG demo workspace: ${WORK_DIR}"
  fi
}
trap cleanup EXIT

cd "${ROOT_DIR}"

run() {
  echo
  echo "+ $*"
  "$@"
}

section() {
  echo
  echo "== $1 =="
}

section "Knowledge graph search example"
(
  cd examples
  run go run ./kg_search_demo
)

section "Knowledge graph cookbook with deterministic vector search"
(
  cd examples
  run go run ./kg_cookbook
)

section "Inline embedded API example"
cat > "${WORK_DIR}/kg_inline.go" <<'GO'
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()
	path := os.Getenv("VELOCITY_KG_PATH")
	if path == "" {
		path = "./kg_inline_demo_db"
	}
	_ = os.RemoveAll(path)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    path,
		DisableEncryption:       true,
		DisableIndexPersistence: true,
	})
	must(err)
	defer func() {
		_ = db.Close()
		_ = os.RemoveAll(path)
	}()

	kg := db.KnowledgeGraph(velocity.KGConfig{
		ChunkMaxWords: 32,
		ChunkOverlap:  8,
		IngestWorkers: 2,
	})
	if kg == nil {
		log.Fatal("knowledge graph engine was nil")
	}

	db.EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []velocity.KGResourceType{velocity.KGResourceKV, velocity.KGResourceObject, velocity.KGResourceSecret, velocity.KGResourceEnvelope, velocity.KGResourceEntity},
		SecretValues:  true,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024 * 1024,
	})

	docs := []*velocity.KGIngestRequest{
		{
			Source:    "security-note.txt",
			MediaType: "text/plain",
			Title:     "Security Note",
			Content:   []byte("Velocity encrypts records, manages secrets, and records audit evidence for compliance teams. Contact secops@example.test."),
			Metadata:  map[string]string{"team": "security", "kind": "note"},
		},
		{
			Source:    "analytics-note.txt",
			MediaType: "text/plain",
			Title:     "Analytics Note",
			Content:   []byte("The knowledge graph chunks documents, extracts entities, and supports keyword and hybrid retrieval."),
			Metadata:  map[string]string{"team": "data", "kind": "note"},
		},
	}

	results, errs := kg.IngestBatch(ctx, docs)
	for i, err := range errs {
		must(err)
		fmt.Printf("ingested[%d]: doc=%s chunks=%d entities=%d\n", i, results[i].DocID[:8], results[i].ChunkCount, results[i].EntityCount)
	}

	search, err := kg.Search(ctx, &velocity.KGSearchRequest{
		Query:   "compliance audit secrets",
		Limit:   5,
		Filters: map[string]string{"team": "security"},
		Mode:    velocity.KGSearchModeKeyword,
	})
	must(err)
	fmt.Printf("filtered search hits: %d mode=%s\n", search.TotalHits, search.Mode)
	for i, hit := range search.Hits {
		fmt.Printf("hit[%d]: source=%s title=%s score=%.4f\n", i, hit.Source, hit.Title, hit.Score)
	}
	fuzzy, err := kg.Search(ctx, &velocity.KGSearchRequest{
		Query:         "complaince secrts",
		Limit:         5,
		Mode:          velocity.KGSearchModeKeyword,
		Fuzzy:         true,
		FuzzyMaxEdits: 1,
	})
	must(err)
	fmt.Printf("fuzzy search hits: %d\n", fuzzy.TotalHits)

	doc, err := kg.GetDocument(results[0].DocID)
	must(err)
	fmt.Printf("retrieved doc: %s source=%s chunks=%d entities=%d\n", doc.ID[:8], doc.Source, doc.ChunkCount, doc.EntityCount)

	analytics := kg.GetAnalytics()
	fmt.Printf("analytics: documents=%d chunks=%d entities=%d\n", analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)

	must(kg.DeleteDocument(results[1].DocID))
	if _, err := kg.GetDocument(results[1].DocID); err != nil {
		fmt.Println("delete verified: analytics-note removed")
	}

	must(db.Put([]byte("customers/acme"), []byte("Acme Corp customer record requires HIPAA review and renewal outreach.")))
	_, err = db.StoreObject("reports/acme-risk.txt", "text/plain", "alice", []byte("Acme Corp object report tracks risk, compliance evidence, and remediation."), nil)
	must(err)
	secret, err := db.CreateSecret(ctx, velocity.SecretRequest{
		Name:  "acme-api-key",
		Value: []byte("secret acme integration token searchable by auto index"),
		Owner: "alice",
	})
	must(err)
	env, err := db.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
		Label:     "Acme KG Envelope",
		Type:      velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy: "alice",
		Payload: velocity.EnvelopePayload{
			Kind:       "note",
			InlineData: []byte("envelope evidence for Acme automatic knowledge graph indexing"),
		},
	})
	must(err)
	entity, err := db.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "Acme Auto KG Entity",
		Data:      json.RawMessage(`{"summary":"entity record indexed automatically into the knowledge graph"}`),
		CreatedBy: "alice",
	})
	must(err)

	autoQueries := []string{
		"HIPAA renewal outreach",
		"object report remediation",
		"secret acme integration",
		"envelope evidence automatic",
		"entity record indexed automatically",
	}
	for _, query := range autoQueries {
		resp, err := kg.Search(ctx, &velocity.KGSearchRequest{Query: query, Limit: 3, Mode: velocity.KGSearchModeKeyword})
		must(err)
		if resp.TotalHits == 0 {
			log.Fatalf("auto-index query %q returned no hits", query)
		}
		hit := resp.Hits[0]
		fmt.Printf("auto-index hit: query=%q source=%s type=%s\n", query, hit.Source, hit.Metadata["resource_type"])
	}
	fmt.Printf("auto-indexed resources: secret=%s envelope=%s entity=%s\n", secret.Version, env.EnvelopeID, entity.EntityID)

	graph, err := kg.SearchResourceGraph(ctx, &velocity.KGResourceGraphRequest{
		Query: "Acme Corp",
		Limit: 10,
		Mode:  velocity.KGSearchModeKeyword,
	})
	must(err)
	fmt.Printf("resource graph: nodes=%d edges=%d\n", len(graph.Nodes), len(graph.Edges))
	for _, edge := range graph.Edges {
		fmt.Printf("resource edge: %s -> %s via %s %q\n", edge.Source, edge.Target, edge.RelationType, edge.Entity.Canonical)
	}

	sqlPath := filepath.Join(path, "sql")
	sqldriver.DSNConfigs[sqlPath] = velocity.Config{
		Path:                                sqlPath,
		DisableEncryption:                   true,
		KnowledgeGraphAutoIndexEnabled:      true,
		KnowledgeGraphAutoIndexResources:    []velocity.KGResourceType{velocity.KGResourceSQLRow},
		KnowledgeGraphAutoIndexMaxValueBytes: 1024 * 1024,
	}
	sqlDB, err := sql.Open(sqldriver.DriverName, sqlPath)
	must(err)
	_, err = sqlDB.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, note TEXT)`)
	must(err)
	_, err = sqlDB.Exec(`INSERT INTO patients (id, note) VALUES (?, ?)`, 1, "sql row indexed automatically for cardiology follow up")
	must(err)
	time.Sleep(300 * time.Millisecond)
	must(sqlDB.Close())
	delete(sqldriver.DSNConfigs, sqlPath)

	sqlVelocityDB, err := velocity.NewWithConfig(velocity.Config{Path: sqlPath, DisableEncryption: true})
	must(err)
	sqlVelocityDB.EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []velocity.KGResourceType{velocity.KGResourceSQLRow},
		SecretValues:  true,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024 * 1024,
	})
	must(sqlVelocityDB.SyncKnowledgeGraph(ctx, velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []velocity.KGResourceType{velocity.KGResourceSQLRow},
		SecretValues:  true,
		Existing:      true,
		Async:         false,
		MaxValueBytes: 1024 * 1024,
	}))
	sqlResp, err := sqlVelocityDB.KnowledgeGraph().Search(ctx, &velocity.KGSearchRequest{Query: "cardiology follow up", Limit: 3, Mode: velocity.KGSearchModeKeyword})
	must(err)
	if sqlResp.TotalHits == 0 {
		log.Fatal("SQL auto-index query returned no hits")
	}
	fmt.Printf("sql auto-index hit: source=%s type=%s\n", sqlResp.Hits[0].Source, sqlResp.Hits[0].Metadata["resource_type"])
	must(sqlVelocityDB.Close())
}
GO
VELOCITY_KG_PATH="${WORK_DIR}/kg_inline_db" run go run "${WORK_DIR}/kg_inline.go"

if [[ "${KG_RUN_BATCH:-}" == "1" ]]; then
  section "Optional batch benchmark"
  (
    cd examples
    run go run -tags velocity_examples ./kg_batch_demo
  )
else
  section "Optional batch benchmark skipped"
  echo "Set KG_RUN_BATCH=1 to run examples/kg_batch_demo."
fi

section "Focused knowledge graph tests"
run go test -run 'TestKGEngine|TestHNSWIndex|TestRuleBasedNER|TestEntityResolver' .

section "Knowledge graph demo completed"

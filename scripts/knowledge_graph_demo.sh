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
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity"
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
		DisableWAL:              true,
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

	doc, err := kg.GetDocument(results[0].DocID)
	must(err)
	fmt.Printf("retrieved doc: %s source=%s chunks=%d entities=%d\n", doc.ID[:8], doc.Source, doc.ChunkCount, doc.EntityCount)

	analytics := kg.GetAnalytics()
	fmt.Printf("analytics: documents=%d chunks=%d entities=%d\n", analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)

	must(kg.DeleteDocument(results[1].DocID))
	if _, err := kg.GetDocument(results[1].DocID); err != nil {
		fmt.Println("delete verified: analytics-note removed")
	}
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

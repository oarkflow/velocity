#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/velocity-feature-flow.XXXXXX")}"
BIN="${WORK_DIR}/velocity"
DB_PATH="${WORK_DIR}/velocity_data"

cleanup() {
  if [[ "${KEEP_FEATURE_FLOW:-}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  else
    echo "Keeping demo workspace: ${WORK_DIR}"
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

section "Build shipped CLI"
run go build -o "${BIN}" ./cmd/velocity
export VELOCITY_PATH="${DB_PATH}"

section "CLI: data, secrets, objects, envelopes, and wrapper dispatch"
run "${BIN}" data put app:name Velocity
run "${BIN}" data get app:name
run "${BIN}" secret set api_key sk_test_feature_flow
run "${BIN}" secret get api_key
run "${BIN}" object put notes/demo.txt
run "${BIN}" object get notes/demo.txt

envelope_id="$("${BIN}" envelope create --label "Feature Flow Envelope" --type court_evidence | awk '/Created envelope:/ {print $3}')"
if [[ -z "${envelope_id}" ]]; then
  echo "failed to parse envelope id" >&2
  exit 1
fi
run "${BIN}" envelope get --id "${envelope_id}"
run "${BIN}" envelope export --id "${envelope_id}" --path "${WORK_DIR}/envelope.json"
run "${BIN}" envelope import --path "${WORK_DIR}/envelope.json"

bundle_id="$("${BIN}" envelope bundle create --label "Feature Flow Bundle" --resource '[{"type":"file","name":"demo.txt","path":"notes/demo.txt"}]' | awk '/Created bundle:/ {print $3}')"
if [[ -z "${bundle_id}" ]]; then
  echo "failed to parse bundle id" >&2
  exit 1
fi
run "${BIN}" envelope bundle list --id "${bundle_id}"
run "${BIN}" envelope bundle resolve --id "${bundle_id}"

VELOCITY_BIN="${BIN}" VELOCITY_PATH="${DB_PATH}" run ./scripts/velocity.sh data get app:name

section "Go API: complete feature families"
cat > "${WORK_DIR}/feature_flow.go" <<'GO'
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
	"github.com/oarkflow/velocity/pkg/s3"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()
	base := os.Getenv("VELOCITY_PATH") + "_go"

	db, err := velocity.NewWithConfig(velocity.Config{Path: base, DisableEncryption: true})
	must(err)
	defer db.Close()

	db.EnableCache(4 * 1024 * 1024)
	db.SetCacheMode("balanced")
	must(db.Put([]byte("core:hello"), []byte("world")))
	got, err := db.Get([]byte("core:hello"))
	must(err)
	fmt.Printf("KV get: %s\n", got)

	must(db.PutWithTTL([]byte("session:123"), []byte("active"), time.Minute))
	ttl, err := db.TTL([]byte("session:123"))
	must(err)
	loginCount, err := db.Incr([]byte("metrics:login"), 1)
	must(err)
	quota, err := db.Decr([]byte("quota:remaining"), 1)
	must(err)
	page, total := db.KeysPage(0, 25)
	scanned := 0
	must(db.Scan([]byte("session:"), func(key, value []byte) bool {
		scanned++
		return true
	}))
	fmt.Printf("TTL/counter/keys/scan: ttl=%t login=%v quota=%v page=%d total=%d scanned=%d\n", ttl > 0, loginCount, quota, len(page), total, scanned)

	bw := db.NewBatchWriter(2)
	must(bw.Put([]byte("batch:1"), []byte("one")))
	must(bw.Put([]byte("batch:2"), []byte("two")))
	must(bw.Flush())
	fmt.Printf("Batch writer flushed: %d\n", bw.Len())

	schema := &velocity.SearchSchema{Fields: []velocity.SearchSchemaField{
		{Name: "title", Searchable: true},
		{Name: "kind", HashSearch: true},
		{Name: "year", ValueIndex: true},
	}}
	db.SetSearchSchemaForPrefix("docs", schema)
	db.EnableSearchIndex(true)
	must(db.Put([]byte("docs:1"), []byte(`{"title":"Velocity compliance guide","kind":"guide","year":2026}`)))
	must(db.Put([]byte("docs:2"), []byte(`{"title":"Velocity object storage cookbook","kind":"guide","year":2025}`)))
	searchHits, err := db.Search(velocity.SearchQuery{
		Prefix:   "docs",
		FullText: "compliance",
		Limit:    10,
	})
	must(err)
	searchCount, err := db.SearchCount(velocity.SearchQuery{Prefix: "docs", FullText: "guide", Limit: 10})
	must(err)
	fmt.Printf("Search hits/count: %d/%d\n", len(searchHits), searchCount)

	bucketMgr := s3.NewBucketManager(db, db)
	must(bucketMgr.CreateBucket("archive", "alice", "us-east-1"))
	must(bucketMgr.SetBucketVersioning("archive", "Enabled"))
	versioning, err := bucketMgr.GetBucketVersioning("archive")
	must(err)
	must(db.CreateFolder("archive/reports/2026", "alice"))
	meta, err := db.StoreObject("archive/reports/2026/q1.txt", "text/plain", "alice", []byte("quarterly report"), nil)
	must(err)
	folders, err := db.ListFolders("archive", true)
	must(err)
	size, objectCount, err := db.GetFolderSize("archive/reports", true)
	must(err)
	must(db.PutObjectTagging("archive", "reports/2026/q1.txt", map[string]string{"class": "internal", "team": "finance"}))
	tags, err := db.GetObjectTagging("archive", "reports/2026/q1.txt")
	must(err)
	fmt.Printf("Objects/folders/S3: path=%s type=%s bytes=%d folders=%d size=%d objects=%d versioning=%s tags=%d\n", meta.Path, meta.ContentType, meta.Size, len(folders), size, objectCount, versioning, len(tags))

	backupPath := filepath.Join(base, "feature-backup.json")
	must(db.Backup(velocity.BackupOptions{
		OutputPath:   backupPath,
		IncludeTypes: []string{"folders"},
		User:         "alice",
		Description:  "feature flow backup",
	}))
	backupMeta, err := db.VerifyBackupIntegrity(backupPath)
	must(err)
	fmt.Printf("Backup verified items: %d\n", backupMeta.ItemCount)

	secretDB, err := velocity.New(filepath.Join(base, "secrets"))
	must(err)
	defer secretDB.Close()
	secret, err := secretDB.CreateSecret(ctx, velocity.SecretRequest{
		Name:  "api-key",
		Value: []byte("sk-live-feature-flow"),
		Owner: "alice",
		Tags:  map[string]string{"env": "demo"},
	})
	must(err)
	secretValue, _, err := secretDB.GetSecretValue(ctx, velocity.SecretRef{Name: secret.Name, Version: secret.Version})
	must(err)
	rotated, err := secretDB.RotateSecret(ctx, velocity.SecretRef{Name: secret.Name, Version: secret.Version})
	must(err)
	fmt.Printf("Secrets: value=%d rotated=%s\n", len(secretValue), rotated.Version)

	envDB, err := velocity.New(filepath.Join(base, "envelopes"))
	must(err)
	defer envDB.Close()
	env, err := envDB.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
		Label:     "API Envelope",
		Type:      velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy: "alice",
		Payload: velocity.EnvelopePayload{
			Kind:         "file",
			ObjectPath:   "feature-flow/evidence.json",
			InlineData:   []byte(`{"case":"feature-flow"}`),
			EncodingHint: "json",
		},
	})
	must(err)
	loadedEnv, err := envDB.LoadEnvelope(ctx, env.EnvelopeID)
	must(err)
	fmt.Printf("Envelope API: %s/%s\n", loadedEnv.EnvelopeID, loadedEnv.Status)

	entityA, err := db.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "patient-123",
		Data:      json.RawMessage(`{"name":"Alice","risk":"low"}`),
		Tags:      map[string]string{"domain": "healthcare"},
		CreatedBy: "alice",
	})
	must(err)
	entityB, err := db.CreateEntity(ctx, &velocity.EntityRequest{
		Type:      velocity.EntityTypeJSON,
		Name:      "visit-456",
		Data:      json.RawMessage(`{"reason":"annual"}`),
		Tags:      map[string]string{"domain": "healthcare"},
		CreatedBy: "alice",
	})
	must(err)
	_, err = db.AddRelation(ctx, &velocity.EntityRelationRequest{
		SourceEntity: entityA.EntityID,
		TargetEntity: entityB.EntityID,
		RelationType: velocity.RelationTypeReferences,
		CreatedBy:    "alice",
	})
	must(err)
	graph, err := db.GetEntityGraph(ctx, entityA.EntityID, 2)
	must(err)
	taggedEntities, err := db.SearchEntitiesByTag(ctx, "domain", "healthcare")
	must(err)
	fmt.Printf("Entities/relations: graph=%d tagged=%d\n", len(graph), len(taggedEntities))

	graphEngine := db.KnowledgeGraph(kg.KGConfig{ChunkMaxWords: 16, ChunkOverlap: 4})
	ingested, err := graphEngine.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "memory://feature-flow",
		MediaType: "text/plain",
		Title:     "Feature Flow Document",
		Content:   []byte("Alice works at Acme Health. Contact alice@example.test for the Velocity compliance graph."),
		Metadata:  map[string]string{"kind": "demo"},
	})
	must(err)
	kgResults, err := graphEngine.Search(ctx, &kg.KGSearchRequest{Query: "Velocity compliance", Limit: 5, Mode: kg.KGSearchModeKeyword})
	must(err)
	analytics := graphEngine.GetAnalytics()
	fmt.Printf("Knowledge graph: doc=%s chunks=%d entities=%d hits=%d analytics_docs=%d\n", ingested.DocID, ingested.ChunkCount, ingested.EntityCount, len(kgResults.Hits), analytics.TotalDocuments)

	sqlPath := filepath.Join(base, "sql")
	sqldriver.DSNConfigs[sqlPath] = velocity.Config{Path: sqlPath, DisableEncryption: true}
	defer delete(sqldriver.DSNConfigs, sqlPath)
	sdb, err := sql.Open(sqldriver.DriverName, sqlPath)
	must(err)
	defer sdb.Close()
	_, err = sdb.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL, role TEXT DEFAULT 'reader')`)
	must(err)
	tx, err := sdb.Begin()
	must(err)
	_, err = tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "alice@example.test", "Alice")
	must(err)
	_, err = tx.Exec(`INSERT INTO users (id, email, name, role) VALUES (?, ?, ?, ?)`, 2, "bob@example.test", "Bob", "admin")
	must(err)
	must(tx.Commit())
	var admins int
	must(sdb.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, "admin").Scan(&admins))
	_, err = sdb.Exec(`UPDATE users SET role = ? WHERE id = ?`, "owner", 1)
	must(err)
	rows, err := sdb.Query(`SELECT name, role FROM users ORDER BY id`)
	must(err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name, role string
		must(rows.Scan(&name, &role))
		names = append(names, name+":"+role)
	}
	must(rows.Err())
	fmt.Printf("SQL: admins=%d rows=%s\n", admins, strings.Join(names, ","))
}
GO
run go run "${WORK_DIR}/feature_flow.go"

section "Compliance feature flow"
KEEP_COMPLIANCE_FLOW="${KEEP_FEATURE_FLOW:-}" run ./scripts/compliance_full_flow.sh

section "Focused validation suites"
run go test -run 'TestComplianceResource|TestComplianceSecretTags|TestEntityManager_CreateEntity|TestEntityManager_AddRelation|TestS3ObjectOps|TestBucketManager' .
run go test ./pkg/sqldriver -run 'TestSQLDriver_TypedDefaultsAndPrimaryKey|TestSQLCompliance' -count=1
run go test ./cmd/velocity -run TestComplianceCLI_TagGetCheck -count=1

section "Feature full flow completed"
echo "Database path used: ${DB_PATH}"

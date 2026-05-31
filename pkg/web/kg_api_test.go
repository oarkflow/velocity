package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestKGAPI_ResourceGraphSyncAndRules(t *testing.T) {
	srv, db := newPentestServer(t)
	token := signToken(t, db.JWTSecret(), jwt.MapClaims{
		"username": "alice",
		"role":     "admin",
	})

	rule := map[string]any{"type": "CUSTOM_ID", "pattern": `CID-\d+`, "confidence": 0.91}
	body, _ := json.Marshal(rule)
	status, resp := request(t, srv, "POST", "/api/v1/kg/ner/rules", token, bytes.NewReader(body), "application/json")
	if status != 201 {
		t.Fatalf("add rule status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "GET", "/api/v1/kg/ner/rules", token, nil, "")
	if status != 200 || !strings.Contains(resp, "CUSTOM_ID") {
		t.Fatalf("list rules status=%d body=%s", status, resp)
	}

	ingest := map[string]any{
		"source":     "kg-api-note",
		"media_type": "text/plain",
		"title":      "KG API Note",
		"content":    []byte("CID-123 mentions CASE-12345 and Acme Corp."),
		"metadata":   map[string]string{"resource_type": "kv", "key": "kg-api-note"},
	}
	body, _ = json.Marshal(ingest)
	status, resp = request(t, srv, "POST", "/api/v1/kg/ingest", token, bytes.NewReader(body), "application/json")
	if status != 201 {
		t.Fatalf("ingest status=%d body=%s", status, resp)
	}

	graphReq := map[string]any{"query": "CID-123 CASE-12345", "limit": 10}
	body, _ = json.Marshal(graphReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/resource-graph", token, bytes.NewReader(body), "application/json")
	if status != 200 {
		t.Fatalf("resource graph status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "GET", "/api/v1/kg/sync/status", token, nil, "")
	if status != 200 {
		t.Fatalf("sync status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "POST", "/api/v1/kg/sync", token, bytes.NewReader([]byte(`{"enabled":true,"existing":true}`)), "application/json")
	if status != 200 {
		t.Fatalf("sync status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "GET", "/api/v1/kg/connectors", token, nil, "")
	if status != 200 || !strings.Contains(resp, "local_file") {
		t.Fatalf("connectors status=%d body=%s", status, resp)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "connector.txt"), []byte("connector HTTP import CASE-77777 for Acme Corp"), 0600); err != nil {
		t.Fatal(err)
	}
	importReq := map[string]any{"connector": "local_file", "path": dir, "limit": 5}
	body, _ = json.Marshal(importReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/connectors/import", token, bytes.NewReader(body), "application/json")
	if status != 201 || !strings.Contains(resp, `"imported":1`) {
		t.Fatalf("connector import status=%d body=%s", status, resp)
	}

	materializeReq := map[string]any{"resource_graph": map[string]any{"query": "Acme Corp", "limit": 10}, "created_by": "http-test"}
	body, _ = json.Marshal(materializeReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/resource-graph/materialize", token, bytes.NewReader(body), "application/json")
	if status != 201 || !strings.Contains(resp, `"created":`) {
		t.Fatalf("materialize resource graph status=%d body=%s", status, resp)
	}

	body, _ = json.Marshal(importReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/jobs", token, bytes.NewReader(body), "application/json")
	if status != 201 || !strings.Contains(resp, `"status":"succeeded"`) {
		t.Fatalf("job start status=%d body=%s", status, resp)
	}
	status, resp = request(t, srv, "GET", "/api/v1/kg/jobs?status=succeeded", token, nil, "")
	if status != 200 || !strings.Contains(resp, `"connector":"local_file"`) {
		t.Fatalf("job list status=%d body=%s", status, resp)
	}

	rowsReq := map[string]any{
		"connector": "static_rows",
		"table":     "cases",
		"rows": []map[string]any{{
			"source":     "case-row-1",
			"media_type": "application/json",
			"title":      "Case Row",
			"metadata":   map[string]string{"table": "cases", "content": `{"case":"CASE-78787","name":"Acme Corp"}`},
		}},
	}
	body, _ = json.Marshal(rowsReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/connectors/import", token, bytes.NewReader(body), "application/json")
	if status != 201 || !strings.Contains(resp, `"imported":1`) {
		t.Fatalf("static rows import status=%d body=%s", status, resp)
	}
}

func TestKGAPI_PersistentRelationsOntologyAndAlgorithms(t *testing.T) {
	srv, db := newPentestServer(t)
	token := signToken(t, db.JWTSecret(), jwt.MapClaims{
		"username": "alice",
		"role":     "admin",
	})

	ontology := map[string]any{
		"name": "default",
		"relation_types": map[string]any{
			"depends_on": map[string]any{
				"allowed_sources": []string{"service"},
				"allowed_targets": []string{"service", "table"},
				"direction":       "out",
				"required_fields": []string{"evidence"},
			},
		},
	}
	body, _ := json.Marshal(ontology)
	status, resp := request(t, srv, "POST", "/api/v1/kg/ontology/validate", token, bytes.NewReader(body), "application/json")
	if status != 200 || !strings.Contains(resp, `"valid":true`) {
		t.Fatalf("validate ontology status=%d body=%s", status, resp)
	}
	status, resp = request(t, srv, "POST", "/api/v1/kg/ontology", token, bytes.NewReader(body), "application/json")
	if status != 201 {
		t.Fatalf("create ontology status=%d body=%s", status, resp)
	}

	relations := []map[string]any{
		{"source": "service:api", "target": "service:worker", "relation_type": "depends_on", "evidence": "api dispatches jobs"},
		{"source": "service:worker", "target": "table:events", "relation_type": "depends_on", "evidence": "worker writes events"},
	}
	var firstID string
	for i, rel := range relations {
		body, _ = json.Marshal(rel)
		status, resp = request(t, srv, "POST", "/api/v1/kg/relations", token, bytes.NewReader(body), "application/json")
		if status != 201 {
			t.Fatalf("create relation %d status=%d body=%s", i, status, resp)
		}
		if i == 0 {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(resp), &decoded); err != nil {
				t.Fatalf("decode relation: %v", err)
			}
			firstID, _ = decoded["relation_id"].(string)
		}
	}

	body, _ = json.Marshal(map[string]any{"source": "service:api"})
	status, resp = request(t, srv, "POST", "/api/v1/kg/relations/query", token, bytes.NewReader(body), "application/json")
	if status != 200 || !strings.Contains(resp, "service:worker") {
		t.Fatalf("query relations status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "GET", "/api/v1/kg/relations/"+firstID, token, nil, "")
	if status != 200 || !strings.Contains(resp, firstID) {
		t.Fatalf("get relation status=%d body=%s", status, resp)
	}

	body, _ = json.Marshal(map[string]any{"seed_ids": []string{"service:api"}, "depth": 2})
	status, resp = request(t, srv, "POST", "/api/v1/kg/query", token, bytes.NewReader(body), "application/json")
	if status != 200 || !strings.Contains(resp, "table:events") {
		t.Fatalf("graph query status=%d body=%s", status, resp)
	}

	body, _ = json.Marshal(map[string]any{"source": "service:api", "target": "table:events", "query": map[string]any{"depth": 3}})
	status, resp = request(t, srv, "POST", "/api/v1/kg/algorithms/path", token, bytes.NewReader(body), "application/json")
	if status != 200 || !strings.Contains(resp, "table:events") {
		t.Fatalf("path status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "POST", "/api/v1/kg/algorithms/metrics", token, bytes.NewReader([]byte(`{}`)), "application/json")
	if status != 200 || !strings.Contains(resp, `"relation_count":2`) {
		t.Fatalf("metrics status=%d body=%s", status, resp)
	}

	status, resp = request(t, srv, "POST", "/api/v1/kg/algorithms/components", token, bytes.NewReader([]byte(`{}`)), "application/json")
	if status != 200 || !strings.Contains(resp, "service:api") {
		t.Fatalf("components status=%d body=%s", status, resp)
	}

	mergeReq := map[string]any{
		"source_ids": []string{"person:alice-old"},
		"target_id":  "person:alice",
		"reason":     "same reviewer",
	}
	body, _ = json.Marshal(mergeReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/entities/merge/propose", token, bytes.NewReader(body), "application/json")
	if status != 201 {
		t.Fatalf("propose merge status=%d body=%s", status, resp)
	}
	var proposal map[string]any
	if err := json.Unmarshal([]byte(resp), &proposal); err != nil {
		t.Fatalf("decode proposal: %v", err)
	}
	proposalID, _ := proposal["proposal_id"].(string)
	status, resp = request(t, srv, "POST", "/api/v1/kg/entities/merge/"+proposalID+"/approve", token, nil, "")
	if status != 200 || !strings.Contains(resp, `"status":"approved"`) {
		t.Fatalf("approve merge status=%d body=%s", status, resp)
	}
	status, resp = request(t, srv, "GET", "/api/v1/kg/entities/resolve/person:alice-old", token, nil, "")
	if status != 200 || !strings.Contains(resp, `"canonical_id":"person:alice"`) {
		t.Fatalf("resolve entity status=%d body=%s", status, resp)
	}
}

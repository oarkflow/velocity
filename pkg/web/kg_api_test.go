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
	if err := os.WriteFile(filepath.Join(dir, "connector.txt"), []byte("connector HTTP import CASE-77777"), 0600); err != nil {
		t.Fatal(err)
	}
	importReq := map[string]any{"connector": "local_file", "path": dir, "limit": 5}
	body, _ = json.Marshal(importReq)
	status, resp = request(t, srv, "POST", "/api/v1/kg/connectors/import", token, bytes.NewReader(body), "application/json")
	if status != 201 || !strings.Contains(resp, `"imported":1`) {
		t.Fatalf("connector import status=%d body=%s", status, resp)
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

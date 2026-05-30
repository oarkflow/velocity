package kg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalFileConnector_ListFetch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(path, []byte("connector import Acme Corp CASE-12345"), 0600); err != nil {
		t.Fatal(err)
	}
	connector := LocalFileConnector{Root: dir}
	items, cursor, err := connector.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if cursor != "" {
		t.Fatalf("expected empty cursor, got %q", cursor)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	req, err := connector.Fetch(context.Background(), items[0])
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if req.Source == "" || req.Title != "note.txt" || string(req.Content) == "" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestStructuredFileConnector_CSVAndJSON(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "customers.csv")
	if err := os.WriteFile(csvPath, []byte("id,name,note\n1,Acme,CASE-11111\n2,Globex,CASE-22222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	csvConnector := StructuredFileConnector{Path: csvPath, Table: "customers"}
	items, _, err := csvConnector.List(context.Background(), "")
	if err != nil {
		t.Fatalf("csv list: %v", err)
	}
	if len(items) != 2 || string(items[0].Content) == "" || items[0].Metadata["table"] != "customers" {
		t.Fatalf("unexpected csv items: %+v", items)
	}

	jsonPath := filepath.Join(dir, "tickets.json")
	if err := os.WriteFile(jsonPath, []byte(`[{"id":"A","note":"CASE-33333"},{"id":"B","note":"CASE-44444"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	jsonConnector := StructuredFileConnector{Path: jsonPath}
	items, _, err = jsonConnector.List(context.Background(), "")
	if err != nil {
		t.Fatalf("json list: %v", err)
	}
	if len(items) != 2 || items[0].MediaType != "application/json" || items[0].Metadata["table"] != "tickets" {
		t.Fatalf("unexpected json items: %+v", items)
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKGCLI_ImportSearchAndNER(t *testing.T) {
	t.Setenv("VELOCITY_PATH", t.TempDir())
	docDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(docDir, "note.txt"), []byte("CLI KG import CASE-88888 for Acme Corp."), 0600); err != nil {
		t.Fatal(err)
	}
	csvPath := filepath.Join(t.TempDir(), "customers.csv")
	if err := os.WriteFile(csvPath, []byte("id,name,note\n1,Acme Corp,CASE-89898\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	oldStdout := os.Stdout
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	}()

	runCmd := func(args ...string) string {
		t.Helper()
		os.Args = append([]string{"velocity"}, args...)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		os.Stdout = w
		err = run()
		_ = w.Close()
		os.Stdout = oldStdout
		if err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		return buf.String()
	}

	out := runCmd("kg", "import", "--connector", "local_file", "--path", docDir, "--format", "text")
	if !strings.Contains(out, "imported=1") {
		t.Fatalf("unexpected import output: %s", out)
	}
	out = runCmd("kg", "import", "--connector", "structured_file", "--file", csvPath, "--table", "customers", "--format", "text")
	if !strings.Contains(out, "imported=1") {
		t.Fatalf("unexpected structured import output: %s", out)
	}
	out = runCmd("kg", "search", "CASE-88888", "--format", "text")
	if !strings.Contains(out, "note.txt") {
		t.Fatalf("unexpected search output: %s", out)
	}
	out = runCmd("kg", "ner", "add", "--type", "CUSTOM_CLI", "--pattern", `CLI-\d+`, "--format", "text")
	if !strings.Contains(out, "CUSTOM_CLI") {
		t.Fatalf("unexpected ner add output: %s", out)
	}
	out = runCmd("kg", "materialize", "Acme Corp", "--limit", "10", "--format", "text")
	if !strings.Contains(out, "created=") || !strings.Contains(out, "relations=") {
		t.Fatalf("unexpected materialize output: %s", out)
	}

	ontologyPath := filepath.Join(t.TempDir(), "ontology.json")
	ontologyJSON := `{"name":"default","relation_types":{"depends_on":{"allowed_sources":["service"],"allowed_targets":["service","table"],"direction":"out","required_fields":["evidence"]}}}`
	if err := os.WriteFile(ontologyPath, []byte(ontologyJSON), 0600); err != nil {
		t.Fatal(err)
	}
	out = runCmd("kg", "ontology", "validate", "--file", ontologyPath)
	if !strings.Contains(out, `"valid": true`) {
		t.Fatalf("unexpected ontology validate output: %s", out)
	}
	_ = runCmd("kg", "ontology", "apply", "--file", ontologyPath)
	out = runCmd("kg", "relation", "create", "--source", "service:api", "--target", "service:worker", "--type", "depends_on", "--evidence", "api dispatches work", "--format", "text")
	if !strings.Contains(out, "service:api -> service:worker") {
		t.Fatalf("unexpected relation create output: %s", out)
	}
	out = runCmd("kg", "relation", "create", "--source", "service:worker", "--target", "table:events", "--type", "depends_on", "--evidence", "worker writes events", "--format", "text")
	if !strings.Contains(out, "service:worker -> table:events") {
		t.Fatalf("unexpected second relation create output: %s", out)
	}
	out = runCmd("kg", "relation", "list", "--source", "service:api", "--format", "text")
	if !strings.Contains(out, "service:worker") {
		t.Fatalf("unexpected relation list output: %s", out)
	}
	out = runCmd("kg", "query", "--seed", "service:api", "--depth", "2", "--format", "text")
	if !strings.Contains(out, "table:events") {
		t.Fatalf("unexpected graph query output: %s", out)
	}
	out = runCmd("kg", "path", "--source", "service:api", "--target", "table:events", "--format", "text")
	if !strings.Contains(out, "service:api -> service:worker -> table:events") {
		t.Fatalf("unexpected path output: %s", out)
	}
	out = runCmd("kg", "entity", "merge", "--target", "person:alice", "--sources", "person:alice-old,person:a.smith", "--reason", "same profile")
	if !strings.Contains(out, `"canonical_id": "person:alice"`) {
		t.Fatalf("unexpected entity merge output: %s", out)
	}
	out = runCmd("kg", "entity", "resolve", "person:alice-old")
	if !strings.Contains(out, `"canonical_id": "person:alice"`) {
		t.Fatalf("unexpected entity resolve output: %s", out)
	}
	out = runCmd("kg", "job", "start", "--connector", "local_file", "--path", docDir)
	if !strings.Contains(out, `"status": "succeeded"`) {
		t.Fatalf("unexpected job start output: %s", out)
	}
	out = runCmd("kg", "job", "list", "--status", "succeeded")
	if !strings.Contains(out, `"connector": "local_file"`) {
		t.Fatalf("unexpected job list output: %s", out)
	}
}

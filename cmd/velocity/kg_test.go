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
}

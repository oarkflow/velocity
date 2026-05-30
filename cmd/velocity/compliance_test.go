package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestComplianceCLI_TagGetCheck(t *testing.T) {
	t.Setenv("VELOCITY_PATH", t.TempDir())
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

	out := runCmd("compliance", "tag", "--type", "secret", "--name", "api-key", "--framework", "GDPR", "--class", "confidential", "--encrypt")
	if !strings.Contains(out, "secret:api-key") {
		t.Fatalf("unexpected tag output: %s", out)
	}
	out = runCmd("compliance", "get", "--type", "secret", "--name", "api-key")
	if !strings.Contains(out, "GDPR") || !strings.Contains(out, "confidential") {
		t.Fatalf("unexpected get output: %s", out)
	}
	out = runCmd("compliance", "check", "--type", "secret", "--name", "api-key", "--operation", "read", "--actor", "alice", "--encrypted")
	if !strings.Contains(out, `"allowed": true`) {
		t.Fatalf("unexpected check output: %s", out)
	}
}

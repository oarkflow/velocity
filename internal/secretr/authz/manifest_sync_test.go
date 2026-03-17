package authz_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedManifestsAreInSync(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// current package dir is internal/secretr/authz
	tmpDir := t.TempDir()

	cmd := exec.Command("go", "run", "./cmd/genmanifests", "-out", tmpDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generator failed: %v\n%s", err, string(out))
	}

	for _, name := range []string{"command_scope_manifest.json", "command_surface_manifest.json"} {
		wantPath := filepath.Join(root, name)
		gotPath := filepath.Join(tmpDir, name)

		want, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatalf("read %s: %v", wantPath, err)
		}
		got, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatalf("read %s: %v", gotPath, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("manifest out of sync: %s\nrun: go run ./internal/secretr/authz/cmd/genmanifests", name)
		}
	}
}

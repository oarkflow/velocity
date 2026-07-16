package velocity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestFileExistsUsesStat(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "shard")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileExists(file) {
		t.Fatal("existing file reported missing")
	}
	if fileExists(filepath.Join(dir, "missing")) {
		t.Fatal("missing file reported present")
	}
}

func TestFileExistsStatError(t *testing.T) {
	old := osStatForIntegrity
	osStatForIntegrity = func(string) (fs.FileInfo, error) {
		return nil, errors.New("injected")
	}
	t.Cleanup(func() { osStatForIntegrity = old })
	if fileExists("ignored") {
		t.Fatal("stat error reported as existing")
	}
}

package preview

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarkflow/previewer/pkg/vfs"

	"github.com/oarkflow/velocity/v2/api"
)

type fakeStore struct {
	objects map[string][]byte
	types   map[string]string
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, types: map[string]string{}}
}

func (f *fakeStore) put(key, contentType string, data []byte) {
	f.objects[key] = data
	f.types[key] = contentType
}

func (f *fakeStore) GetObject(_ context.Context, _, key, _ string) (io.ReadCloser, api.ObjectMeta, error) {
	data, ok := f.objects[key]
	if !ok {
		return nil, api.ObjectMeta{}, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), api.ObjectMeta{Key: key, Size: int64(len(data)), ContentType: f.types[key]}, nil
}

func (f *fakeStore) ListObjects(_ context.Context, _, prefix string) ([]api.ObjectMeta, error) {
	var out []api.ObjectMeta
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, api.ObjectMeta{Key: k, Size: int64(len(v)), ContentType: f.types[k]})
		}
	}
	return out, nil
}

// stubViewer replaces the blocking viewer for the duration of a test.
// The captured function sees the materialised paths while the viewer is "open".
func stubViewer(t *testing.T, onFile func(string), onFolder func(string, vfs.Options)) {
	t.Helper()
	origFile, origFolder := previewFile, previewFolder
	t.Cleanup(func() { previewFile, previewFolder = origFile, origFolder })
	previewFile = func(p string) error {
		if onFile != nil {
			onFile(p)
		}
		return nil
	}
	previewFolder = func(dir string, opts vfs.Options) error {
		if onFolder != nil {
			onFolder(dir, opts)
		}
		return nil
	}
}

func TestViewObjectMaterialisesAndCleansUp(t *testing.T) {
	store := newFakeStore()
	store.put("docs/readme", "text/markdown", []byte("# hello"))

	var seenPath string
	stubViewer(t, func(p string) {
		seenPath = p
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("file not readable during preview: %v", err)
		}
		if string(data) != "# hello" {
			t.Fatalf("unexpected content %q", data)
		}
		if filepath.Ext(p) != ".md" {
			t.Fatalf("expected .md extension from content type, got %q", p)
		}
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
		}
	}, nil)

	if err := ViewObject(context.Background(), store, "b", "docs/readme"); err != nil {
		t.Fatalf("ViewObject: %v", err)
	}
	if _, err := os.Stat(seenPath); !os.IsNotExist(err) {
		t.Fatalf("temp file not removed after preview: %v", err)
	}
}

func TestViewObjectMissing(t *testing.T) {
	stubViewer(t, nil, nil)
	if err := ViewObject(context.Background(), newFakeStore(), "b", "nope.txt"); err == nil {
		t.Fatal("expected error for missing object")
	}
}

func TestViewFolderMaterialisesTree(t *testing.T) {
	store := newFakeStore()
	store.put("proj/a.txt", "text/plain", []byte("A"))
	store.put("proj/sub/b.txt", "text/plain", []byte("B"))
	store.put("other/c.txt", "text/plain", []byte("C"))

	var seenDir string
	stubViewer(t, nil, func(dir string, opts vfs.Options) {
		seenDir = dir
		if opts.MaxFileSize <= 0 || opts.MaxTotalSize <= 0 {
			t.Fatalf("zero limits must not reach the viewer: %+v", opts)
		}
		for rel, want := range map[string]string{"a.txt": "A", "sub/b.txt": "B"} {
			data, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				t.Fatalf("missing %s: %v", rel, err)
			}
			if string(data) != want {
				t.Fatalf("%s: got %q want %q", rel, data, want)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "c.txt")); !os.IsNotExist(err) {
			t.Fatal("object outside prefix must not be materialised")
		}
	})

	if err := ViewFolder(context.Background(), store, "b", "proj", FolderOptions{}); err != nil {
		t.Fatalf("ViewFolder: %v", err)
	}
	if _, err := os.Stat(seenDir); !os.IsNotExist(err) {
		t.Fatalf("temp directory not removed after preview: %v", err)
	}
}

func TestViewFolderEmpty(t *testing.T) {
	stubViewer(t, nil, nil)
	if err := ViewFolder(context.Background(), newFakeStore(), "b", "empty", FolderOptions{}); err == nil {
		t.Fatal("expected error for empty folder")
	}
}

func TestViewFolderLimits(t *testing.T) {
	store := newFakeStore()
	store.put("p/big.bin", "application/octet-stream", make([]byte, 100))
	stubViewer(t, nil, nil)

	if err := ViewFolder(context.Background(), store, "b", "p/", FolderOptions{MaxFileSize: 10}); err == nil {
		t.Fatal("expected per-file size error")
	}
	if err := ViewFolder(context.Background(), store, "b", "p/", FolderOptions{MaxTotalSize: 10}); err == nil {
		t.Fatal("expected total size error")
	}
}

func TestViewFolderRejectsTraversalKeys(t *testing.T) {
	store := newFakeStore()
	store.put("p/../escape.txt", "text/plain", []byte("x"))
	stubViewer(t, nil, func(string, vfs.Options) {
		t.Fatal("viewer must not run when a key escapes the folder")
	})
	if err := ViewFolder(context.Background(), store, "b", "p", FolderOptions{}); err == nil {
		t.Fatal("expected unsafe path error")
	}
}

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"", ".", "..", "../x", "/abs", "a/../../x"} {
		if _, err := safeJoin(root, bad); err == nil {
			t.Errorf("safeJoin(%q) should fail", bad)
		}
	}
	got, err := safeJoin(root, "a/b.txt")
	if err != nil || got != filepath.Join(root, "a", "b.txt") {
		t.Fatalf("safeJoin ok case: %q, %v", got, err)
	}
}

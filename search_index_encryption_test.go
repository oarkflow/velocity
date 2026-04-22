package velocity

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchEncryptedDataAfterReopen(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	dir := t.TempDir()
	schema := map[string]*SearchSchema{
		"users": {
			Fields: []SearchSchemaField{
				{Name: "name", Searchable: true},
				{Name: "email", HashSearch: true},
				{Name: "age", HashSearch: true},
			},
		},
	}

	db, err := NewWithConfig(Config{
		Path:          dir,
		MasterKey:     key,
		SearchSchemas: schema,
	})
	if err != nil {
		t.Fatalf("NewWithConfig failed: %v", err)
	}

	records := map[string]string{
		"users:1": `{"name":"John Carter","email":"john.carter@example.com","age":35}`,
		"users:2": `{"name":"John Doe","email":"john.doe@example.com","age":29}`,
		"users:3": `{"name":"Jane Roe","email":"jane.roe@example.com","age":41}`,
	}

	for key, value := range records {
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("Put(%s) failed: %v", key, err)
		}
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	assertNoPlaintextTermLeak(t, dir, []string{"John", "john.carter@example.com", "Jane Roe"})

	reopened, err := NewWithConfig(Config{
		Path:          dir,
		MasterKey:     key,
		SearchSchemas: schema,
	})
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	results, err := reopened.Search(SearchQuery{
		Prefix:   "users",
		FullText: "john",
		Filters: []SearchFilter{
			{Field: "email", Op: "==", Value: "john.carter@example.com", HashOnly: true},
			{Field: "age", Op: ">=", Value: 30},
		},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if got := string(results[0].Key); got != "users:1" {
		t.Fatalf("unexpected result key %q", got)
	}
	if !bytes.Contains(results[0].Value, []byte(`"John Carter"`)) {
		t.Fatalf("unexpected result payload: %s", results[0].Value)
	}

	count, err := reopened.SearchCount(SearchQuery{
		Prefix: "users",
		Filters: []SearchFilter{
			{Field: "email", Op: "==", Value: "john.carter@example.com", HashOnly: true},
			{Field: "age", Op: ">=", Value: 30},
		},
	})
	if err != nil {
		t.Fatalf("SearchCount failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected SearchCount=1, got %d", count)
	}
}

func assertNoPlaintextTermLeak(t *testing.T, dir string, terms []string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	foundSSTable := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "sst_") || filepath.Ext(entry.Name()) != ".db" {
			continue
		}
		foundSSTable = true
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%s) failed: %v", entry.Name(), err)
		}
		for _, term := range terms {
			if bytes.Contains(raw, []byte(term)) {
				t.Fatalf("plaintext term %q leaked into %s", term, entry.Name())
			}
		}
	}

	if !foundSSTable {
		t.Fatal("expected at least one SSTable after close")
	}
}

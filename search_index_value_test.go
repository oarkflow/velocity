package velocity

import (
	"fmt"
	"testing"
)

func TestSearchValueIndexBatchWriterRangeCount(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
		DisableFsync:      true,
		SearchSchemas: map[string]*SearchSchema{
			"users": {
				Fields: []SearchSchemaField{
					{Name: "id", Searchable: true, HashSearch: true},
					{Name: "email", HashSearch: true},
					{Name: "age", Searchable: true, HashSearch: true, ValueIndex: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig failed: %v", err)
	}
	defer db.Close()

	batch := db.NewBatchWriter(100)
	for i := 0; i < 1000; i++ {
		record := fmt.Sprintf(`{"id":%d,"email":"user_%d@example.com","age":%d}`, i, i, 20+(i%50))
		if err := batch.Put([]byte(fmt.Sprintf("users:%d", i)), []byte(record)); err != nil {
			t.Fatalf("batch put failed: %v", err)
		}
	}
	if err := batch.Flush(); err != nil {
		t.Fatalf("batch flush failed: %v", err)
	}

	if got := len(db.valueIndexPostings[valueIndexValuesKey("users", "age")]); got != 50 {
		t.Fatalf("expected 50 indexed age buckets, got %d", got)
	}
	if !db.hasHashIndexFieldLocked("users", "email") {
		t.Fatalf("expected email hash index marker to be populated")
	}

	count, err := db.SearchCount(SearchQuery{
		Prefix: "users",
		Filters: []SearchFilter{
			{Field: "age", Op: ">=", Value: 30},
		},
	})
	if err != nil {
		t.Fatalf("SearchCount failed: %v", err)
	}
	if count != 800 {
		t.Fatalf("expected 800 matching users, got %d", count)
	}

	results, err := db.Search(SearchQuery{
		Prefix: "users",
		Filters: []SearchFilter{
			{Field: "email", Op: "==", Value: "missing@example.com"},
			{Field: "age", Op: ">=", Value: 30},
		},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results for missing indexed email, got %d", len(results))
	}
}

func TestSearchExactIDUsesPrimaryKeyWithoutHashIndex(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
		DisableFsync:      true,
		SearchSchemas: map[string]*SearchSchema{
			"users": {
				Fields: []SearchSchemaField{
					{Name: "age", ValueIndex: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig failed: %v", err)
	}
	defer db.Close()

	if err := db.Put([]byte("users:42"), []byte(`{"id":42,"age":34}`)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	results, err := db.Search(SearchQuery{
		Prefix: "users",
		Filters: []SearchFilter{
			{Field: "id", Op: "==", Value: 42, HashOnly: true},
		},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 || string(results[0].Key) != "users:42" {
		t.Fatalf("expected primary-key result users:42, got %#v", results)
	}

	count, err := db.SearchCount(SearchQuery{
		Prefix: "users",
		Filters: []SearchFilter{
			{Field: "id", Op: "==", Value: 42, HashOnly: true},
		},
	})
	if err != nil {
		t.Fatalf("SearchCount failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

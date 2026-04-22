//go:build velocity_longtests
// +build velocity_longtests

package velocity

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
)

func TestSearchIndexLargeDataset(t *testing.T) {
	records := 1_000_000
	if v := os.Getenv("VELOCITY_RECORDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			records = n
		}
	}

	dir := t.TempDir()
	db, err := NewWithConfig(Config{Path: dir})
	if err != nil {
		t.Fatalf("NewWithConfig failed: %v", err)
	}
	defer db.Close()

	schema := &SearchSchema{Fields: []SearchSchemaField{
		{Name: "email", Searchable: false, HashSearch: true},
		{Name: "age", Searchable: true, HashSearch: false},
		{Name: "location", Searchable: true, HashSearch: true},
		{Name: "name", Searchable: true, HashSearch: false},
	}}

	db.SetSearchSchemaForPrefix("users", schema)
	db.EnableSearchIndex(true)

	rand.Seed(7)
	locations := []string{"london", "paris", "berlin", "madrid"}
	firstNames := []string{"john", "jane", "alex", "emma"}

	for i := 0; i < records; i++ {
		name := firstNames[rand.Intn(len(firstNames))]
		loc := locations[rand.Intn(len(locations))]
		age := 18 + rand.Intn(60)
		email := fmt.Sprintf("%s%06d@example.com", name, i)
		value := fmt.Sprintf(`{"email":"%s","age":%d,"location":"%s","name":"%s"}`, email, age, loc, name)
		key := fmt.Sprintf("users:%d", i)
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("put failed: %v", err)
		}
	}

	results, err := db.Search(SearchQuery{
		Prefix:   "users",
		FullText: "john",
		Filters: []SearchFilter{
			{Field: "location", Op: "==", Value: "london", HashOnly: true},
			{Field: "age", Op: ">", Value: 25},
		},
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected some results, got 0")
	}
}
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity"
)

func main() {
	dir := filepath.Join(os.TempDir(), "velocity-fulltext-demo")
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path: dir,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"articles": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "title", Searchable: true},
					{Name: "body", Searchable: true},
					{Name: "category", ValueIndex: true},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mustPut(db, "articles:1", `{"id":"1","category":"search","title":"Fast full text search","body":"Velocity supports phrase search, prefix search, ranking, and snippets."}`)
	mustPut(db, "articles:2", `{"id":"2","category":"security","title":"Object lock and audit","body":"Compliance workflows use immutable audit trails and legal hold."}`)
	mustPut(db, "articles:3", `{"id":"3","category":"search","title":"Retrieval notes","body":"Search retrieval retrieval retrieval can be scored by term frequency."}`)

	runQuery(db, "phrase", velocity.SearchQuery{
		Prefix:    "articles",
		FullText:  `"full text search"`,
		Highlight: true,
	})
	runQuery(db, "boolean", velocity.SearchQuery{
		Prefix:    "articles",
		FullText:  "compliance OR retrieval",
		MatchMode: "boolean",
		Highlight: true,
	})
	runQuery(db, "prefix + filter", velocity.SearchQuery{
		Prefix:   "articles",
		FullText: "retriev*",
		Filters:  []velocity.SearchFilter{{Field: "category", Op: "==", Value: "search"}},
		Limit:    10,
	})
	runQuery(db, "nested grouped condition", velocity.SearchQuery{
		Prefix:    "articles",
		Highlight: true,
		Condition: &velocity.SearchCondition{
			Bool: "AND",
			Children: []velocity.SearchCondition{
				{
					Bool:      "OR",
					Fields:    []string{"title", "body"},
					FullText:  "retrieval OR compliance",
					MatchMode: "boolean",
				},
				{
					Field:  "category",
					Op:     "==",
					Values: []any{"search", "security"},
				},
				{
					Not:      true,
					Field:    "body",
					FullText: "expired",
				},
			},
		},
	})
}

func mustPut(db *velocity.DB, key, value string) {
	if err := db.Put([]byte(key), []byte(value)); err != nil {
		log.Fatalf("put %s: %v", key, err)
	}
}

func runQuery(db *velocity.DB, name string, query velocity.SearchQuery) {
	if query.Limit == 0 {
		query.Limit = 5
	}
	results, err := db.Search(query)
	if err != nil {
		log.Fatalf("%s search: %v", name, err)
	}
	fmt.Printf("\n%s\n", name)
	for _, result := range results {
		fmt.Printf("- %s score=%.2f\n", result.Key, result.Score)
		for _, snippet := range result.Highlights["$value"] {
			fmt.Printf("  %s\n", snippet)
		}
	}
}

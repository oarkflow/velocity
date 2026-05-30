package velocity

import (
	"bytes"
	"testing"
)

func TestSearchFullTextAdvancedQueryModes(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path: t.TempDir(),
		SearchSchemas: map[string]*SearchSchema{
			"docs": {
				Fields: []SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "title", Searchable: true},
					{Name: "body", Searchable: true},
					{Name: "kind", ValueIndex: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig failed: %v", err)
	}
	defer db.Close()

	records := map[string]string{
		"docs:1": `{"id":"1","kind":"guide","title":"Fast full text search","body":"Velocity provides robust full text retrieval with ranking ranking ranking"}`,
		"docs:2": `{"id":"2","kind":"guide","title":"Compliance audit log","body":"Immutable compliance evidence and legal hold workflows"}`,
		"docs:3": `{"id":"3","kind":"note","title":"Text ordering","body":"Retrieval text full appears shuffled here"}`,
		"docs:4": `{"id":"4","kind":"guide","title":"Prefix matching","body":"Retrieve retrieved retrieval documents quickly"}`,
	}
	for key, value := range records {
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("Put(%s) failed: %v", key, err)
		}
	}

	assertKeys := func(name string, q SearchQuery, want ...string) {
		t.Helper()
		q.Prefix = "docs"
		q.Limit = 10
		results, err := db.Search(q)
		if err != nil {
			t.Fatalf("%s: Search failed: %v", name, err)
		}
		got := make([]string, len(results))
		for i, result := range results {
			got[i] = string(result.Key)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got keys %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: got keys %v, want %v", name, got, want)
			}
		}
		count, err := db.SearchCount(q)
		if err != nil {
			t.Fatalf("%s: SearchCount failed: %v", name, err)
		}
		if count != len(want) {
			t.Fatalf("%s: count=%d, want %d", name, count, len(want))
		}
	}
	assertKeySet := func(name string, q SearchQuery, want ...string) {
		t.Helper()
		q.Prefix = "docs"
		q.Limit = 10
		results, err := db.Search(q)
		if err != nil {
			t.Fatalf("%s: Search failed: %v", name, err)
		}
		got := make(map[string]struct{}, len(results))
		for _, result := range results {
			got[string(result.Key)] = struct{}{}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %v results %#v, want %v", name, len(got), got, want)
		}
		for _, key := range want {
			if _, ok := got[key]; !ok {
				t.Fatalf("%s: missing key %s in %#v", name, key, got)
			}
		}
		count, err := db.SearchCount(q)
		if err != nil {
			t.Fatalf("%s: SearchCount failed: %v", name, err)
		}
		if count != len(want) {
			t.Fatalf("%s: count=%d, want %d", name, count, len(want))
		}
	}

	assertKeys("and terms", SearchQuery{FullText: "full retrieval"}, "docs:1", "docs:3")
	assertKeys("or terms", SearchQuery{FullText: "compliance OR ranking", MatchMode: "boolean"}, "docs:1", "docs:2")
	assertKeys("negative term", SearchQuery{FullText: "full -shuffled"}, "docs:1")
	assertKeys("phrase", SearchQuery{FullText: `"full text retrieval"`}, "docs:1")
	assertKeys("prefix", SearchQuery{FullText: "documents retriev*"}, "docs:4")
	assertKeys("filter plus text", SearchQuery{
		FullText: "compliance",
		Filters:  []SearchFilter{{Field: "kind", Op: "==", Value: "guide"}},
	}, "docs:2")
	assertKeySet("nested boolean condition", SearchQuery{
		Condition: &SearchCondition{
			Bool: "AND",
			Children: []SearchCondition{
				{
					Bool:      "OR",
					Fields:    []string{"title", "body"},
					FullText:  "compliance OR retrieval",
					MatchMode: "boolean",
				},
				{
					Field:  "kind",
					Op:     "==",
					Values: []any{"guide"},
				},
				{
					Not:      true,
					Field:    "body",
					FullText: "shuffled",
				},
			},
		},
	}, "docs:4", "docs:1", "docs:2")
	assertKeys("multi value field condition", SearchQuery{
		Condition: &SearchCondition{
			Bool:   "OR",
			Field:  "kind",
			Op:     "==",
			Values: []any{"note", "missing"},
		},
	}, "docs:3")

	results, err := db.Search(SearchQuery{Prefix: "docs", FullText: "ranking", Limit: 10, Highlight: true})
	if err != nil {
		t.Fatalf("ranking search failed: %v", err)
	}
	if len(results) == 0 || string(results[0].Key) != "docs:1" || results[0].Score <= 1 {
		t.Fatalf("expected repeated ranking term to score first, got %#v", results)
	}
	if !bytes.Contains(results[0].Value, []byte("ranking ranking ranking")) {
		t.Fatalf("unexpected top result: %s", results[0].Value)
	}
	if len(results[0].Highlights["$value"]) == 0 {
		t.Fatalf("expected full-text highlight, got %#v", results[0].Highlights)
	}
}

package sqldriver

import (
	"database/sql"
	"os"
	"testing"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_FullTextLike(t *testing.T) {
	os.RemoveAll("./testdb_fulltext")
	defer os.RemoveAll("./testdb_fulltext")

	DSNConfigs["./testdb_fulltext"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"articles": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", Searchable: true, HashSearch: true},
					{Name: "title", Searchable: true},
					{Name: "body", Searchable: true},
				},
			},
		},
	}
	defer delete(DSNConfigs, "./testdb_fulltext")

	db, err := sql.Open("velocity", "./testdb_fulltext")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO articles (id, title, body) VALUES (1, 'Vector Search', 'Velocity supports full text retrieval')`); err != nil {
		t.Fatalf("insert 1 failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO articles (id, title, body) VALUES (2, 'Audit Trails', 'Immutable compliance log')`); err != nil {
		t.Fatalf("insert 2 failed: %v", err)
	}

	rows, err := db.Query(`SELECT title FROM articles WHERE title LIKE '%vector%'`)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	var titles []string
	for rows.Next() {
		var title string
		if err := rows.Scan(&title); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		titles = append(titles, title)
	}

	if len(titles) != 1 || titles[0] != "Vector Search" {
		t.Fatalf("unexpected titles: %#v", titles)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM articles WHERE body LIKE '%retrieval%'`).Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count=1, got %d", count)
	}
}

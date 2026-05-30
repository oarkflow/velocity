package sqldriver

import (
	"database/sql"
	"os"
	"testing"
)

func TestSQLDriver_FullTextLike(t *testing.T) {
	os.RemoveAll("./testdb_fulltext")
	defer os.RemoveAll("./testdb_fulltext")

	db, err := sql.Open("velocity", "./testdb_fulltext")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE articles (
		uuid string PRIMARY KEY,
		id int INDEX,
		title string,
		body string FULLTEXT,
		kind string INDEX,
		views int VALUEINDEX
	)`); err != nil {
		t.Fatalf("create table failed: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO articles (uuid, id, title, body, kind, views) VALUES ('article-1', 1, 'Vector Search', 'Velocity supports full text retrieval', 'search', 120)`); err != nil {
		t.Fatalf("insert 1 failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO articles (uuid, id, title, body, kind, views) VALUES ('article-2', 2, 'Audit Trails', 'Immutable compliance log', 'audit', 40)`); err != nil {
		t.Fatalf("insert 2 failed: %v", err)
	}

	rows, err := db.Query(`SELECT title FROM articles WHERE body LIKE '%retrieval%'`)
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

	if err := db.QueryRow(`SELECT COUNT(*) FROM articles WHERE kind = 'search' AND views >= 100`).Scan(&count); err != nil {
		t.Fatalf("indexed count query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected indexed count=1, got %d", count)
	}
}

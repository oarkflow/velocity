package sqldriver

import (
	"database/sql"
	"os"
	"testing"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_NonHashEqualityFallsBackToScan(t *testing.T) {
	os.RemoveAll("./testdb_hash_fallback")
	defer os.RemoveAll("./testdb_hash_fallback")

	DSNConfigs["./testdb_hash_fallback"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "name", Searchable: true},
					{Name: "age", Searchable: true, HashSearch: true},
				},
			},
		},
	}

	db, err := sql.Open("velocity", "./testdb_hash_fallback")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("INSERT INTO users (name, age) VALUES (?, ?)", "Alice", 30); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM users WHERE name = 'Alice'").Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row, got %d", count)
	}
}

func TestSQLDriver_SelectNotLimitedTo1000(t *testing.T) {
	os.RemoveAll("./testdb_select_limit")
	defer os.RemoveAll("./testdb_select_limit")

	DSNConfigs["./testdb_select_limit"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", Searchable: true, HashSearch: true},
				},
			},
		},
	}

	db, err := sql.Open("velocity", "./testdb_select_limit")
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	stmt, err := tx.Prepare("INSERT INTO users (id) VALUES (?)")
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	for i := 0; i < 1205; i++ {
		if _, err := stmt.Exec(i); err != nil {
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("stmt close failed: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1205 {
		t.Fatalf("expected 1205 rows, got %d", count)
	}
}

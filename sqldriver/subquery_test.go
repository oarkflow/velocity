package sqldriver

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_Subquery(t *testing.T) {
	os.RemoveAll("./testdb_subquery")
	defer os.RemoveAll("./testdb_subquery")

	schemaItems := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "item_id", Searchable: true, HashSearch: true},
			{Name: "price", Searchable: true},
			{Name: "status", Searchable: true},
		},
	}

	DSNConfigs["./testdb_subquery"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"items": schemaItems,
		},
	}

	db, err := sql.Open("velocity", "./testdb_subquery")
	if err != nil {
		t.Fatalf("Failed to open driver: %v", err)
	}
	defer db.Close()

	// 1. Insert Items
	_, _ = db.Exec("INSERT INTO items (item_id, price, status) VALUES (?, ?, ?)", 1, 10.5, "active")
	_, _ = db.Exec("INSERT INTO items (item_id, price, status) VALUES (?, ?, ?)", 2, 50.0, "active")
	_, _ = db.Exec("INSERT INTO items (item_id, price, status) VALUES (?, ?, ?)", 3, 100.0, "inactive")

	time.Sleep(500 * time.Millisecond) // await index

	// 2. Execute Subquery
	query := `
		SELECT sub.item_id, sub.price
		FROM (
			SELECT item_id, price
			FROM items
			WHERE status = 'active'
		) AS sub
		WHERE sub.price > ?
	`
	rows, err := db.Query(query, 20.0)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var itemID int
		var price float64
		if err := rows.Scan(&itemID, &price); err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		if itemID != 2 {
			t.Errorf("Expected item_id=2, got %d", itemID)
		}
		if price != 50.0 {
			t.Errorf("Expected price=50.0, got %f", price)
		}
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 item from subquery, got %d", count)
	}
}

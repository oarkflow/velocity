package sqldriver

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_Joins(t *testing.T) {
	os.RemoveAll("./testdb_joins")
	defer os.RemoveAll("./testdb_joins")

	schemaUsers := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "id", Searchable: true, HashSearch: true},
			{Name: "name", Searchable: true},
		},
	}
	schemaOrders := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "order_id", Searchable: true, HashSearch: true},
			{Name: "user_id", Searchable: true, HashSearch: true},
			{Name: "total", Searchable: true},
		},
	}

	DSNConfigs["./testdb_joins"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users":  schemaUsers,
			"orders": schemaOrders,
		},
	}

	db, err := sql.Open("velocity", "./testdb_joins")
	if err != nil {
		t.Fatalf("Failed to open driver: %v", err)
	}
	defer db.Close()

	// 1. Insert Users
	_, _ = db.Exec("INSERT INTO users (id, name) VALUES (?, ?)", 1, "Alice")
	_, _ = db.Exec("INSERT INTO users (id, name) VALUES (?, ?)", 2, "Bob")

	// 2. Insert Orders
	_, _ = db.Exec("INSERT INTO orders (order_id, user_id, total) VALUES (?, ?, ?)", 100, 1, 55.5)
	_, _ = db.Exec("INSERT INTO orders (order_id, user_id, total) VALUES (?, ?, ?)", 101, 1, 20.0)
	_, _ = db.Exec("INSERT INTO orders (order_id, user_id, total) VALUES (?, ?, ?)", 102, 2, 99.9)

	time.Sleep(500 * time.Millisecond) // await index

	// 3. Execute JOIN
	query := `
		SELECT u.name, o.total
		FROM users u
		JOIN orders o ON u.id = o.user_id
		WHERE u.name = 'Alice' AND o.total > ?
	`
	rows, err := db.Query(query, 50.0)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var name string
		var total float64
		if err := rows.Scan(&name, &total); err != nil {
			t.Fatalf("Scan failed: %v", err)
		}
		if name != "Alice" {
			t.Errorf("Expected Alice, got %s", name)
		}
		if total <= 50.0 {
			t.Errorf("Expected total > 50, got %f", total)
		}
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 order for Alice > 50, got %d", count)
	}
}

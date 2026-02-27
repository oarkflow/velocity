package sqldriver

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_InsertAndSelect(t *testing.T) {
	os.RemoveAll("./testdb")
	defer os.RemoveAll("./testdb")

	schema := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "name", Searchable: true},
			{Name: "age", Searchable: true, HashSearch: true},
		},
	}

	DSNConfigs["./testdb"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": schema,
		},
	}

	db, err := sql.Open("velocity", "./testdb")

	// 1. Insert rows
	res, err := db.Exec("INSERT INTO users (name, age) VALUES (?, ?)", "Alice", 30)
	if err != nil {
		t.Fatalf("Insert Alice failed: %v", err)
	}

	res, err = db.Exec("INSERT INTO users (name, age) VALUES (?, ?)", "Bob", 40)
	if err != nil {
		t.Fatalf("Insert Bob failed: %v", err)
	}

	affected, _ := res.RowsAffected()
	if affected != 1 {
		t.Errorf("Expected 1 row affected, got %d", affected)
	}

	// Wait for async index to catch up
	time.Sleep(500 * time.Millisecond)

	// 2. Select rows
	rows, err := db.Query("SELECT name, age FROM users WHERE age >= ?", 30)
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var name string
		var age float64 // json.Unmarshal decodes numbers as float64 into interface{} mapping usually
		err := rows.Scan(&name, &age)
		if err != nil {
			t.Fatalf("Row scan failed: %v", err)
		}
		if name != "Alice" && name != "Bob" {
			t.Errorf("Unexpected user: %s", name)
		}
		count++
	}

	if count != 2 {
		t.Errorf("Expected 2 users, found %d", count)
	}

	// 3. Update Row
	res, err = db.Exec("UPDATE users SET age = ? WHERE name = 'Alice'", 31)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// 4. Delete Row
	res, err = db.Exec("DELETE FROM users WHERE name = 'Bob'")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	rows, err = db.Query("SELECT name, age FROM users")
	if err != nil {
		t.Fatalf("Final select failed: %v", err)
	}
	defer rows.Close()

	count = 0
	for rows.Next() {
		var name string
		var age float64
		_ = rows.Scan(&name, &age)
		if name != "Alice" {
			t.Errorf("Expected only Alice, got %s", name)
		}
		if age != 31 {
			t.Errorf("Expected Alice age to be 31, got %v", age)
		}
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 user remaining, found %d", count)
	}
}

func TestSQLDriver_OpContext(t *testing.T) {
	db, err := sql.Open("velocity", "./testdb2")
	if err != nil {
		t.Fatalf("Failed to open velocity driver: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll("./testdb2")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, "INSERT INTO items (id, val) VALUES (?, ?)", 1, "test")
	if err != nil {
		t.Fatalf("ExecContext failed: %v", err)
	}
}

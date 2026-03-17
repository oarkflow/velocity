package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/sqldriver"
)

func main() {
	dbPath := "./demo_sql_db"
	_ = os.RemoveAll(dbPath)
	defer os.RemoveAll(dbPath)

	// Velocity requires schemas to understand indexing and typing before we can issue queries.
	schema := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "name", Searchable: true},
			{Name: "role", Searchable: true, HashSearch: true},
			{Name: "age", Searchable: true},
		},
	}

	// We can inject schemas directly into the driver configs for database/sql usage.
	sqldriver.DSNConfigs[dbPath] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"employees": schema,
		},
	}

	// Connect to Velocity via standard Go database/sql driver
	db, err := sql.Open("velocity", dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Insert records using standard SQL Exec
	fmt.Println("--- Inserting Records ---")
	_, err = db.ExecContext(ctx, "INSERT INTO employees (name, role, age) VALUES (?, ?, ?)", "Alice", "Engineer", 28)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.ExecContext(ctx, "INSERT INTO employees (name, role, age) VALUES (?, ?, ?)", "Bob", "Manager", 45)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.ExecContext(ctx, "INSERT INTO employees (name, role, age) VALUES (?, ?, ?)", "Charlie", "Engineer", 35)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Records inserted successfully.")

	// 2. Querying records using SQL
	fmt.Println("--- Querying Records ---")
	rows, err := db.QueryContext(ctx, "SELECT name, role, age FROM employees WHERE role = 'Engineer' AND age >= ?", 25)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var role string
		var age float64 // numeric JSON parsing falls back to float64
		_ = rows.Scan(&name, &role, &age)
		fmt.Printf("Found: %s, %s (Age: %.0f)\n", name, role, age)
	}
	fmt.Println()

	// 3. Updating existing records using SQL
	fmt.Println("--- Updating Records ---")
	res, err := db.ExecContext(ctx, "UPDATE employees SET role = ? WHERE name = 'Alice'", "Senior Engineer")
	if err != nil {
		log.Fatal(err)
	}
	affected, _ := res.RowsAffected()
	fmt.Printf("Updated %d record(s)\n\n", affected)

	// 4. Deleting records
	fmt.Println("--- Deleting Records ---")
	res, err = db.ExecContext(ctx, "DELETE FROM employees WHERE role = 'Manager'")
	if err != nil {
		log.Fatal(err)
	}
	deleted, _ := res.RowsAffected()
	fmt.Printf("Deleted %d record(s)\n\n", deleted)

	// Summary
	fmt.Println("--- Final Employee List ---")
	rows2, _ := db.Query("SELECT name, role FROM employees")
	for rows2.Next() {
		var name, role string
		_ = rows2.Scan(&name, &role)
		fmt.Printf("- %s (%s)\n", name, role)
	}
}

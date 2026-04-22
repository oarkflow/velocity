package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/sqldriver"
)

func main() {
	path := "./sql_crud_demo_db"
	_ = os.RemoveAll(path)
	defer os.RemoveAll(path)

	sqldriver.DSNConfigs[path] = velocity.Config{
		Path: path,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", Searchable: true, HashSearch: true},
					{Name: "name", Searchable: true},
					{Name: "email", Searchable: true, HashSearch: true},
					{Name: "age", Searchable: true},
				},
			},
		},
	}
	defer delete(sqldriver.DSNConfigs, path)

	db, err := sql.Open(sqldriver.DriverName, path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ctx := context.Background()

	fmt.Println("=== Velocity SQL CRUD Demo ===")
	fmt.Println()

	if _, err := db.ExecContext(ctx, `CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, email TEXT, age BIGINT)`); err != nil {
		panic(err)
	}
	fmt.Println("CREATE: users table created")

	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, name, email, age) VALUES (?, ?, ?, ?)`, 1, "Alice", "alice@acme.io", 29); err != nil {
		panic(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, name, email, age) VALUES (?, ?, ?, ?)`, 2, "Bob", "bob@acme.io", 35); err != nil {
		panic(err)
	}
	fmt.Println("INSERT: two users added")

	fmt.Println()
	fmt.Println("READ:")
	rows, err := db.QueryContext(ctx, `SELECT id, name, email, age FROM users ORDER BY id ASC`)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var id int
		var name, email string
		var age int
		if err := rows.Scan(&id, &name, &email, &age); err != nil {
			rows.Close()
			panic(err)
		}
		fmt.Printf("  user=%d %s <%s> age=%d\n", id, name, email, age)
	}
	rows.Close()

	if _, err := db.ExecContext(ctx, `UPDATE users SET age = age + 1 WHERE id = ?`, 1); err != nil {
		panic(err)
	}
	var updatedAge int
	if err := db.QueryRowContext(ctx, `SELECT age FROM users WHERE id = ?`, 1).Scan(&updatedAge); err != nil {
		panic(err)
	}
	fmt.Println()
	fmt.Printf("UPDATE: Alice age is now %d\n", updatedAge)

	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, 2); err != nil {
		panic(err)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&remaining); err != nil {
		panic(err)
	}
	fmt.Println()
	fmt.Printf("DELETE: remaining user count = %d\n", remaining)
}

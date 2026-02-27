package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity"
	_ "github.com/oarkflow/velocity/sqldriver"
)

func main() {
	path := "./sql_demo_db"
	cfg := velocity.Config{
		Path: path,
	}

	db, err := velocity.NewWithConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to open velocity: %v", err)
	}
	defer db.Close()

	// Use standard database/sql for complex queries
	sqlDB, err := sql.Open("velocity", path)
	if err != nil {
		log.Fatalf("Failed to open sql connection: %v", err)
	}
	defer sqlDB.Close()

	ctx := context.Background()

	fmt.Println("=== 📊 Velocity Advanced SQL Demo ===")

	// 1. Setup sample data (Velocity is schema-less, table name acts as a key prefix)
	setupQueries := []string{
		"INSERT INTO departments (id, name) VALUES (10, 'Engineering')",
		"INSERT INTO departments (id, name) VALUES (20, 'Sales')",
		"INSERT INTO employees (id, name, dept_id, salary) VALUES (1, 'Alice', 10, 150000)",
		"INSERT INTO employees (id, name, dept_id, salary) VALUES (2, 'Bob', 10, 120000)",
		"INSERT INTO employees (id, name, dept_id, salary) VALUES (3, 'Charlie', 20, 100000)",
	}

	for _, q := range setupQueries {
		if _, err := sqlDB.ExecContext(ctx, q); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
	}

	// 2. Complex JOIN & Projections
	fmt.Println("\n[1] Complex JOIN with Projections...")
	joinQuery := `
		SELECT e.name as employee, d.name as department
		FROM employees e
		JOIN departments d ON e.dept_id = d.id
		WHERE e.salary > 110000
	`
	rows, err := sqlDB.QueryContext(ctx, joinQuery)
	if err != nil {
		log.Fatalf("Join query failed: %v", err)
	}
	fmt.Println("Results:")
	for rows.Next() {
		var name, dept string
		if err := rows.Scan(&name, &dept); err != nil {
			log.Fatal(err)
		}
		fmt.Printf(" - %s works in %s\n", name, dept)
	}
	rows.Close()

	// 3. Subquery
	fmt.Println("\n[2] Subquery in WHERE clause...")
	subquery := `
		SELECT name FROM employees
		WHERE dept_id IN (SELECT id FROM departments WHERE name = 'Engineering')
	`
	rows, err = sqlDB.QueryContext(ctx, subquery)
	if err != nil {
		log.Fatalf("Subquery failed: %v", err)
	}
	fmt.Println("Engineering Team:")
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatal(err)
		}
		fmt.Printf(" - %s\n", name)
	}
	rows.Close()

	// 4. UNION ALL
	fmt.Println("\n[3] UNION ALL Query...")
	unionQuery := `
		SELECT name FROM employees WHERE dept_id = 10
		UNION ALL
		SELECT name FROM departments
	`
	rows, err = sqlDB.QueryContext(ctx, unionQuery)
	if err != nil {
		log.Fatalf("Union query failed: %v", err)
	}
	fmt.Println("Combined names (Employees + Departments):")
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatal(err)
		}
		fmt.Printf(" - %s\n", name)
	}
	rows.Close()

	fmt.Println("\n=== ✅ SQL Demo Completed ===")

	// Cleanup
	_ = os.RemoveAll(path)
}

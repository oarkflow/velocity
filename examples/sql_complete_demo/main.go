package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/sqldriver"
)

func main() {
	if err := runSQLExamples(); err != nil {
		panic(err)
	}
	if err := runComparisonBenchmark(); err != nil {
		panic(err)
	}
}

func runSQLExamples() error {
	path := "./sql_complete_demo_db"
	_ = os.RemoveAll(path)
	defer os.RemoveAll(path)

	schema := map[string]*velocity.SearchSchema{
		"customers": {
			Fields: []velocity.SearchSchemaField{
				{Name: "id", Searchable: true, HashSearch: true},
				{Name: "name", Searchable: true},
				{Name: "region", Searchable: true, HashSearch: true},
				{Name: "spend", Searchable: true},
				{Name: "status", Searchable: true, HashSearch: true},
			},
		},
		"orders": {
			Fields: []velocity.SearchSchemaField{
				{Name: "id", Searchable: true, HashSearch: true},
				{Name: "customer_id", Searchable: true, HashSearch: true},
				{Name: "total", Searchable: true},
				{Name: "state", Searchable: true, HashSearch: true},
			},
		},
	}

	sqlDB, cleanup, err := openSQLDB(path, schema)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()

	fmt.Println("=== Velocity SQL Complete Demo ===")
	fmt.Println()

	setupQueries := []string{
		`CREATE TABLE customers (id BIGINT PRIMARY KEY, name TEXT, region TEXT, spend BIGINT, status TEXT)`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, customer_id BIGINT, total BIGINT, state TEXT)`,
		`INSERT INTO customers (id, name, region, spend, status) VALUES
			(1, 'Alice', 'emea', 2400, 'active'),
			(2, 'Bob', 'amer', 900, 'trial'),
			(3, 'Charlie', 'emea', 1800, 'active'),
			(4, 'Diana', 'apac', 3000, 'active')`,
		`INSERT INTO orders (id, customer_id, total, state) VALUES
			(100, 1, 1200, 'paid'),
			(101, 1, 800, 'paid'),
			(102, 2, 300, 'draft'),
			(103, 3, 900, 'paid'),
			(104, 4, 1500, 'paid')`,
	}
	for _, query := range setupQueries {
		if _, err := sqlDB.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("setup query failed: %w", err)
		}
	}

	fmt.Println("1. Filter + ORDER BY + LIMIT")
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT name, region, spend
		FROM customers
		WHERE status = 'active' AND spend >= 1800
		ORDER BY spend DESC
		LIMIT 3
	`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, region string
		var spend float64
		if err := rows.Scan(&name, &region, &spend); err != nil {
			rows.Close()
			return err
		}
		fmt.Printf("   %s from %s spent %.0f\n", name, region, spend)
	}
	rows.Close()
	fmt.Println()

	fmt.Println("2. JOIN")
	rows, err = sqlDB.QueryContext(ctx, `
		SELECT c.name, o.total
		FROM customers c
		JOIN orders o ON c.id = o.customer_id
		WHERE o.state = 'paid' AND o.total >= 900
		ORDER BY o.total DESC
	`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		var total float64
		if err := rows.Scan(&name, &total); err != nil {
			rows.Close()
			return err
		}
		fmt.Printf("   %s has a paid order of %.0f\n", name, total)
	}
	rows.Close()
	fmt.Println()

	fmt.Println("3. GROUP BY + HAVING")
	rows, err = sqlDB.QueryContext(ctx, `
		SELECT c.region, COUNT(*) AS customer_count, SUM(c.spend) AS total_spend
		FROM customers c
		GROUP BY c.region
		HAVING SUM(c.spend) >= 2000
		ORDER BY total_spend DESC
	`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var region string
		var count int
		var spend float64
		if err := rows.Scan(&region, &count, &spend); err != nil {
			rows.Close()
			return err
		}
		fmt.Printf("   %s => customers=%d total_spend=%.0f\n", region, count, spend)
	}
	rows.Close()
	fmt.Println()

	fmt.Println("4. Subquery")
	rows, err = sqlDB.QueryContext(ctx, `
		SELECT name
		FROM customers
		WHERE id IN (
			SELECT customer_id
			FROM orders
			WHERE total >= 1000
		)
		ORDER BY name ASC
	`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		fmt.Printf("   customer with large order: %s\n", name)
	}
	rows.Close()
	fmt.Println()

	fmt.Println("5. Full-text search via SQL LIKE")
	rows, err = sqlDB.QueryContext(ctx, `
		SELECT name
		FROM customers
		WHERE name LIKE '%ice%'
		ORDER BY name ASC
	`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		fmt.Printf("   full-text match: %s\n", name)
	}
	rows.Close()
	fmt.Println()

	fmt.Println("6. UPDATE + DELETE")
	if _, err := sqlDB.ExecContext(ctx, `UPDATE customers SET spend = spend + 500 WHERE name = 'Bob'`); err != nil {
		return err
	}
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM orders WHERE state = 'draft'`); err != nil {
		return err
	}

	var bobSpend float64
	if err := sqlDB.QueryRowContext(ctx, `SELECT spend FROM customers WHERE name = 'Bob'`).Scan(&bobSpend); err != nil {
		return err
	}
	var orderCount int
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM orders`).Scan(&orderCount); err != nil {
		return err
	}
	fmt.Printf("   Bob spend after update: %.0f\n", bobSpend)
	fmt.Printf("   Remaining orders after delete: %d\n", orderCount)
	fmt.Println()

	return nil
}

func runComparisonBenchmark() error {
	const (
		rowCount    = 2000
		iterations  = 500
		targetID    = 777
		minAgeFloor = 40
	)

	nativePath := "./sql_complete_native_bench_db"
	sqlPath := "./sql_complete_sql_bench_db"
	_ = os.RemoveAll(nativePath)
	_ = os.RemoveAll(sqlPath)
	defer os.RemoveAll(nativePath)
	defer os.RemoveAll(sqlPath)

	schema := map[string]*velocity.SearchSchema{
		"users": {
			Fields: []velocity.SearchSchemaField{
				{Name: "id", Searchable: true, HashSearch: true},
				{Name: "name", Searchable: true},
				{Name: "age", Searchable: true, HashSearch: true},
			},
		},
	}

	nativeDB, err := velocity.NewWithConfig(velocity.Config{
		Path:            nativePath,
		SearchSchemas:   schema,
		PerformanceMode: "performance",
	})
	if err != nil {
		return err
	}
	defer nativeDB.Close()

	sqlDB, cleanup, err := openSQLDB(sqlPath, schema)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := seedNativeUsers(nativeDB, rowCount); err != nil {
		return err
	}
	if err := seedSQLUsers(sqlDB, rowCount); err != nil {
		return err
	}

	fmt.Println("=== Native vs SQL Benchmark ===")
	fmt.Printf("Rows: %d, Iterations per operation: %d\n", rowCount, iterations)
	fmt.Println()

	results := []benchmarkResult{
		runTimed("Native Insert", iterations, func(i int) error {
			id := rowCount + i + 1
			payload, err := json.Marshal(map[string]interface{}{
				"id":   id,
				"name": fmt.Sprintf("native_insert_%d", id),
				"age":  20 + (id % 50),
			})
			if err != nil {
				return err
			}
			return nativeDB.Put([]byte(fmt.Sprintf("users:%d", id)), payload)
		}),
	}

	insertStmt, err := sqlDB.PrepareContext(context.Background(), `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()
	results = append(results, runTimed("SQL Insert", iterations, func(i int) error {
		id := rowCount + i + 1
		_, err := insertStmt.ExecContext(context.Background(), id, fmt.Sprintf("sql_insert_%d", id), 20+(id%50))
		return err
	}))

	results = append(results, runTimed("Native Read", iterations, func(i int) error {
		_, err := nativeDB.Get([]byte(fmt.Sprintf("users:%d", (i%rowCount)+1)))
		return err
	}))

	readStmt, err := sqlDB.PrepareContext(context.Background(), `SELECT name, age FROM users WHERE id = ?`)
	if err != nil {
		return err
	}
	defer readStmt.Close()
	results = append(results, runTimed("SQL Read", iterations, func(i int) error {
		var name string
		var age int
		return readStmt.QueryRowContext(context.Background(), (i%rowCount)+1).Scan(&name, &age)
	}))

	results = append(results, runTimed("Native SearchCount", iterations, func(i int) error {
		_, err := nativeDB.SearchCount(velocity.SearchQuery{
			Prefix: "users",
			Filters: []velocity.SearchFilter{
				{Field: "age", Op: ">=", Value: minAgeFloor},
			},
		})
		return err
	}))

	results = append(results, runTimed("SQL COUNT(*)", iterations, func(i int) error {
		var count int
		return sqlDB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM users WHERE age >= ?`, minAgeFloor).Scan(&count)
	}))

	results = append(results, runTimed("Native Point Read", iterations, func(i int) error {
		_, err := nativeDB.Get([]byte(fmt.Sprintf("users:%d", targetID)))
		return err
	}))

	results = append(results, runTimed("SQL Point Read", iterations, func(i int) error {
		var name string
		var age int
		return readStmt.QueryRowContext(context.Background(), targetID).Scan(&name, &age)
	}))

	for _, result := range results {
		fmt.Printf("%-18s total=%-12v avg=%-12v ops/sec=%.2f\n", result.name, result.total, result.avg, result.opsPerSec)
	}
	fmt.Println()

	return nil
}

type benchmarkResult struct {
	name      string
	total     time.Duration
	avg       time.Duration
	opsPerSec float64
}

func runTimed(name string, iterations int, fn func(i int) error) benchmarkResult {
	start := time.Now()
	success := 0
	for i := 0; i < iterations; i++ {
		if err := fn(i); err == nil {
			success++
		}
	}
	total := time.Since(start)
	if success == 0 {
		return benchmarkResult{name: name, total: total, avg: total, opsPerSec: 0}
	}
	return benchmarkResult{
		name:      name,
		total:     total,
		avg:       total / time.Duration(success),
		opsPerSec: float64(success) / total.Seconds(),
	}
}

func openSQLDB(path string, schema map[string]*velocity.SearchSchema) (*sql.DB, func(), error) {
	sqldriver.DSNConfigs[path] = velocity.Config{
		Path:            path,
		SearchSchemas:   schema,
		PerformanceMode: "performance",
	}
	db, err := sql.Open(sqldriver.DriverName, path)
	if err != nil {
		delete(sqldriver.DSNConfigs, path)
		return nil, nil, err
	}
	cleanup := func() {
		_ = db.Close()
		delete(sqldriver.DSNConfigs, path)
	}
	return db, cleanup, nil
}

func seedNativeUsers(db *velocity.DB, count int) error {
	batch := db.NewBatchWriter(count)
	for i := 1; i <= count; i++ {
		payload, err := json.Marshal(map[string]interface{}{
			"id":   i,
			"name": fmt.Sprintf("native_user_%d", i),
			"age":  20 + (i % 50),
		})
		if err != nil {
			return err
		}
		if err := batch.Put([]byte(fmt.Sprintf("users:%d", i)), payload); err != nil {
			return err
		}
	}
	return batch.Flush()
}

func seedSQLUsers(db *sql.DB, count int) error {
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for i := 1; i <= count; i++ {
		if _, err := stmt.ExecContext(ctx, i, fmt.Sprintf("sql_user_%d", i), 20+(i%50)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

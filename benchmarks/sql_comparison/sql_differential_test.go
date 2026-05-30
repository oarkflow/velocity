package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

func TestVelocitySQLDifferentialAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	velocityDB := openDifferentialVelocityDB(t, "velocity_diff")
	sqliteDB := openDifferentialSQLiteDB(t)
	defer velocityDB.Close()
	defer sqliteDB.Close()

	schemaAndData := []string{
		`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL, age BIGINT, active BIGINT)`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total BIGINT, status TEXT)`,
		`INSERT INTO users (id, email, name, age, active) VALUES
			(1, 'alice@example.test', 'Alice', 30, 1),
			(2, 'bob@example.test', 'Bob', 41, 1),
			(3, NULL, 'Cara', NULL, 0),
			(4, NULL, 'Dana', 35, 1)`,
		`INSERT INTO orders (id, user_id, total, status) VALUES
			(10, 1, 125, 'paid'),
			(11, 1, 20, 'open'),
			(12, 2, 75, 'paid'),
			(13, 4, 75, 'paid')`,
	}
	for _, stmt := range schemaAndData {
		if _, err := velocityDB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("velocity exec %q failed: %v", stmt, err)
		}
		if _, err := sqliteDB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("sqlite exec %q failed: %v", stmt, err)
		}
	}

	queries := []struct {
		name string
		sql  string
		args []any
	}{
		{name: "point lookup", sql: `SELECT name, age FROM users WHERE id = ?`, args: []any{1}},
		{name: "null predicate", sql: `SELECT id, name FROM users WHERE email IS NULL ORDER BY id`},
		{name: "aggregate", sql: `SELECT status, COUNT(*), SUM(total) FROM orders GROUP BY status ORDER BY status`},
		{name: "join", sql: `SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.status = ? ORDER BY users.name, orders.id`, args: []any{"paid"}},
		{name: "cte", sql: `
			WITH paid AS (
				SELECT user_id, SUM(total) AS paid_total
				FROM orders
				WHERE status = 'paid'
				GROUP BY user_id
			)
			SELECT users.name, paid.paid_total
			FROM users JOIN paid ON users.id = paid.user_id
			WHERE paid.paid_total >= ?
			ORDER BY users.name`, args: []any{75}},
		{name: "in subquery", sql: `SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total >= ?) ORDER BY name`, args: []any{75}},
		{name: "left join", sql: `SELECT users.name, orders.status FROM users LEFT JOIN orders ON users.id = orders.user_id AND orders.status = 'open' ORDER BY users.name, orders.id`},
	}
	for _, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			velocityRows := mustCanonicalRows(t, velocityDB, query.sql, query.args...)
			sqliteRows := mustCanonicalRows(t, sqliteDB, query.sql, query.args...)
			if strings.Join(velocityRows, "\n") != strings.Join(sqliteRows, "\n") {
				t.Fatalf("velocity/sqlite mismatch\nvelocity:\n%s\nsqlite:\n%s", strings.Join(velocityRows, "\n"), strings.Join(sqliteRows, "\n"))
			}
		})
	}

	t.Run("constraints and rollback", func(t *testing.T) {
		tx, err := velocityDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("velocity begin failed: %v", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, email, name, age, active) VALUES (?, ?, ?, ?, ?)`, 5, "eve@example.test", "Eve", 20, 1); err != nil {
			_ = tx.Rollback()
			t.Fatalf("velocity tx insert failed: %v", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatalf("velocity rollback failed: %v", err)
		}
		var count int
		if err := velocityDB.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id = ?`, 5).Scan(&count); err != nil {
			t.Fatalf("velocity rollback count failed: %v", err)
		}
		if count != 0 {
			t.Fatalf("velocity rollback leaked row count=%d", count)
		}
		if _, err := velocityDB.ExecContext(ctx, `INSERT INTO users (id, email, name, age, active) VALUES (?, ?, ?, ?, ?)`, 6, "alice@example.test", "Alicia", 31, 1); err == nil {
			t.Fatalf("velocity accepted duplicate unique email")
		}
	})
}

func openDifferentialVelocityDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	_ = os.RemoveAll(path)
	sqldriver.DSNConfigs[path] = velocity.Config{
		Path:              path,
		DisableEncryption: true,
		DisableWAL:        true,
		DisableFsync:      true,
		PerformanceMode:   "performance",
	}
	t.Cleanup(func() {
		delete(sqldriver.DSNConfigs, path)
		_ = os.RemoveAll(path)
	})
	db, err := sql.Open(sqldriver.DriverName, path)
	if err != nil {
		t.Fatalf("open velocity failed: %v", err)
	}
	return db
}

func openDifferentialSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	if _, err := db.Exec(`PRAGMA temp_store = MEMORY`); err != nil {
		_ = db.Close()
		t.Fatalf("sqlite pragma failed: %v", err)
	}
	return db
}

func mustCanonicalRows(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns failed: %v", err)
	}
	out := make([]string, 0)
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		parts := make([]string, len(values))
		for i, value := range values {
			parts[i] = canonicalSQLValue(value)
		}
		out = append(out, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows failed: %v", err)
	}
	sort.Strings(out)
	return out
}

func canonicalSQLValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "<NULL>"
	case []byte:
		return string(v)
	case int64:
		return fmt.Sprintf("%.6f", float64(v))
	case int:
		return fmt.Sprintf("%.6f", float64(v))
	case float64:
		if math.Trunc(v) == v {
			return fmt.Sprintf("%.6f", v)
		}
		return fmt.Sprintf("%g", v)
	default:
		return fmt.Sprint(v)
	}
}

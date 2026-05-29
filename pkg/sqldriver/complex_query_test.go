package sqldriver

import (
	"database/sql"
	"path/filepath"
	"sort"
	"testing"

	"github.com/oarkflow/velocity"
)

func openComplexQueryDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	DSNConfigs[path] = velocity.Config{
		Path:              path,
		DisableEncryption: true,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "name", Searchable: true},
					{Name: "active", HashSearch: true},
				},
			},
			"orders": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "user_id", HashSearch: true},
					{Name: "total", ValueIndex: true},
					{Name: "status", HashSearch: true},
				},
			},
		},
	}
	t.Cleanup(func() {
		delete(DSNConfigs, path)
	})
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	for _, stmt := range []string{
		`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, active BIGINT)`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total BIGINT, status TEXT)`,
		`INSERT INTO users (id, name, active) VALUES (1, 'Alice', 1), (2, 'Bob', 1), (3, 'Cara', 0)`,
		`INSERT INTO orders (id, user_id, total, status) VALUES (10, 1, 125, 'paid'), (11, 1, 20, 'open'), (12, 2, 75, 'paid')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q failed: %v", stmt, err)
		}
	}
	return db
}

func TestSQLDriver_ComplexCTEJoinAggregateHaving(t *testing.T) {
	db := openComplexQueryDB(t, "cte_join_aggregate")
	rows, err := db.Query(`
		WITH active_users AS (
			SELECT id, name FROM users WHERE active = 1
		), paid_totals AS (
			SELECT user_id, SUM(total) AS total_paid
			FROM orders
			WHERE status = 'paid'
			GROUP BY user_id
			HAVING SUM(total) >= 75
		)
		SELECT au.name, pt.total_paid
		FROM active_users au
		JOIN paid_totals pt ON au.id = pt.user_id
		ORDER BY pt.total_paid DESC
	`)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var name string
		var total float64
		if err := rows.Scan(&name, &total); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		got = append(got, name)
		if name == "Alice" && total != 125 {
			t.Fatalf("Alice total = %v, want 125", total)
		}
		if name == "Bob" && total != 75 {
			t.Fatalf("Bob total = %v, want 75", total)
		}
	}
	want := []string{"Alice", "Bob"}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rows = %v, want %v", got, want)
		}
	}
}

func TestSQLDriver_ComplexCTEColumnAliasesAndInExistsSubqueries(t *testing.T) {
	db := openComplexQueryDB(t, "cte_subqueries")
	rows, err := db.Query(`
		WITH paid(uid, amount) AS (
			SELECT user_id, total FROM orders WHERE status = 'paid'
		)
		SELECT name
		FROM users
		WHERE id IN (SELECT uid FROM paid WHERE amount >= 75)
		  AND EXISTS (SELECT amount FROM paid WHERE paid.uid = users.id)
		ORDER BY name
	`)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		got = append(got, name)
	}
	if len(got) != 2 || got[0] != "Alice" || got[1] != "Bob" {
		t.Fatalf("names = %v, want [Alice Bob]", got)
	}
}

func TestSQLDriver_ComplexOuterJoins(t *testing.T) {
	db := openComplexQueryDB(t, "outer_joins")
	rows, err := db.Query(`
		SELECT u.name, o.total
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id AND o.status = 'paid'
		ORDER BY u.name
	`)
	if err != nil {
		t.Fatalf("left join failed: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]int)
	for rows.Next() {
		var name string
		var total sql.NullFloat64
		if err := rows.Scan(&name, &total); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		seen[name]++
	}
	if seen["Alice"] != 1 || seen["Bob"] != 1 || seen["Cara"] != 1 {
		t.Fatalf("left join names = %#v, want Alice/Bob/Cara", seen)
	}
}

func TestSQLDriver_ComplexSetOperations(t *testing.T) {
	db := openComplexQueryDB(t, "set_ops")
	rows, err := db.Query(`
		WITH paid_users AS (
			SELECT user_id AS id FROM orders WHERE status = 'paid'
		)
		SELECT id FROM users WHERE active = 1
		INTERSECT
		SELECT id FROM paid_users
		ORDER BY id
	`)
	if err != nil {
		t.Fatalf("intersect failed: %v", err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		got = append(got, id)
	}
	sort.Ints(got)
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("ids = %v, want [1 2]", got)
	}
}

func TestSQLDriver_RecursiveCTERejected(t *testing.T) {
	db := openComplexQueryDB(t, "recursive_rejected")
	if _, err := db.Query(`
		WITH RECURSIVE nums(n) AS (
			SELECT 1
			UNION ALL
			SELECT n + 1 FROM nums WHERE n < 3
		)
		SELECT n FROM nums
	`); err == nil {
		t.Fatalf("expected recursive CTE to be rejected")
	}
}

func TestSQLDriver_ComplexCreateViewAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "views")
	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, active BIGINT)`); err != nil {
		t.Fatalf("create users failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total BIGINT, status TEXT)`); err != nil {
		t.Fatalf("create orders failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name, active) VALUES (1, 'Alice', 1), (2, 'Bob', 1), (3, 'Cara', 0)`); err != nil {
		t.Fatalf("insert users failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO orders (id, user_id, total, status) VALUES (10, 1, 125, 'paid'), (11, 1, 20, 'open'), (12, 2, 75, 'paid')`); err != nil {
		t.Fatalf("insert orders failed: %v", err)
	}
	if _, err := db.Exec(`
		CREATE VIEW paid_user_totals (name, total_paid) AS
		SELECT u.name, SUM(o.total) AS total_paid
		FROM users u
		JOIN orders o ON u.id = o.user_id
		WHERE o.status = 'paid'
		GROUP BY u.name
	`); err != nil {
		t.Fatalf("create view failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	reopened, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()
	rows, err := reopened.Query(`SELECT name, total_paid FROM paid_user_totals WHERE total_paid >= 75 ORDER BY total_paid DESC`)
	if err != nil {
		t.Fatalf("query view failed: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		var total float64
		if err := rows.Scan(&name, &total); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		got = append(got, name)
	}
	if len(got) != 2 || got[0] != "Alice" || got[1] != "Bob" {
		t.Fatalf("view rows = %v, want [Alice Bob]", got)
	}
}

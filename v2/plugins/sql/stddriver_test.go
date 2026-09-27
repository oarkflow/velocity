package sql

import (
	"context"
	"testing"
)

// TestStdDriver_RoundTrip proves the database/sql adapter actually works
// end to end through the real stdlib API (sql.DB.Exec/Query, rows.Scan) —
// not just that it compiles against the driver.* interfaces.
func TestStdDriver_RoundTrip(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(newMemKV())

	db, err := Open(engine)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "CREATE TABLE users (id INT PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	res, err := db.ExecContext(ctx, "INSERT INTO users (id, name) VALUES (?, ?)", 1, "alice")
	if err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("RowsAffected: got %d, %v, want 1, nil", n, err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO users (id, name) VALUES (?, ?)", 2, "bob"); err != nil {
		t.Fatalf("INSERT 2: %v", err)
	}

	rows, err := db.QueryContext(ctx, "SELECT id, name FROM users WHERE id = ?", 1)
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatalf("expected a row, got none (err: %v)", rows.Err())
	}
	var id int64
	var name string
	if err := rows.Scan(&id, &name); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if id != 1 || name != "alice" {
		t.Fatalf("got (%d, %q), want (1, \"alice\")", id, name)
	}
	if rows.Next() {
		t.Fatalf("expected exactly one row for id=1")
	}

	// LastInsertId is documented as unsupported — confirm it fails clearly
	// rather than silently returning 0 as if it were meaningful.
	if _, err := res.LastInsertId(); err == nil {
		t.Fatalf("expected LastInsertId to return an error (documented as unsupported)")
	}
}

// TestStdDriver_Prepare proves the driver.Stmt path (db.Prepare, not just
// the ExecerContext/QueryerContext fast path) also works.
func TestStdDriver_Prepare(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(newMemKV())
	db, err := Open(engine)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	stmt, err := db.PrepareContext(ctx, "INSERT INTO t (id, v) VALUES (?, ?)")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	for i, v := range []string{"a", "b", "c"} {
		if _, err := stmt.ExecContext(ctx, i, v); err != nil {
			t.Fatalf("prepared Exec(%d): %v", i, err)
		}
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) AS c FROM t").Scan(&count); err != nil {
		t.Fatalf("QueryRow COUNT: %v", err)
	}
	if count != 3 {
		t.Fatalf("got count %d, want 3", count)
	}
}

// TestStdDriver_Transaction proves db.Begin/Commit/Rollback route through
// the same Engine.Begin/Tx used by the api.SQLEngine path.
func TestStdDriver_Transaction(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(newMemKV())
	db, err := Open(engine)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO t (id, v) VALUES (?, ?)", 1, "x"); err != nil {
		t.Fatalf("tx Exec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) AS c FROM t").Scan(&count); err != nil {
		t.Fatalf("QueryRow COUNT: %v", err)
	}
	if count != 0 {
		t.Fatalf("got count %d after rollback, want 0", count)
	}
}

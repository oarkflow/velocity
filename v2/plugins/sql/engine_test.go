package sql

import (
	"context"
	"testing"
)

func TestCreateInsertSelect(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())

	if _, err := eng.Exec(ctx, `CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255), age INT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := eng.Exec(ctx, `INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)`); err != nil {
		t.Fatalf("insert 1: %v", err)
	}
	if _, err := eng.Exec(ctx, `INSERT INTO users (id, name, age) VALUES (2, 'Bob', 25)`); err != nil {
		t.Fatalf("insert 2: %v", err)
	}

	rows, err := eng.Query(ctx, `SELECT * FROM users WHERE id = 1`)
	if err != nil {
		t.Fatalf("select by pk: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["name"] != "Alice" {
		t.Fatalf("expected Alice, got %v", rows[0]["name"])
	}

	rows, err = eng.Query(ctx, `SELECT * FROM users WHERE age > 20`)
	if err != nil {
		t.Fatalf("select with filter: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	rows, err = eng.Query(ctx, `SELECT name FROM users WHERE age > 27`)
	if err != nil {
		t.Fatalf("select projected: %v", err)
	}
	if len(rows) != 1 || rows[0]["name"] != "Alice" {
		t.Fatalf("expected only Alice, got %v", rows)
	}
}

func TestUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())

	mustExec(t, eng, `CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255), age INT)`)
	mustExec(t, eng, `INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)`)
	mustExec(t, eng, `INSERT INTO users (id, name, age) VALUES (2, 'Bob', 25)`)

	n, err := eng.Exec(ctx, `UPDATE users SET age = 31 WHERE id = 1`)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row affected, got %d", n)
	}
	rows, err := eng.Query(ctx, `SELECT * FROM users WHERE id = 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("select after update: rows=%v err=%v", rows, err)
	}
	age, _ := numeric(rows[0]["age"])
	if age != 31 {
		t.Fatalf("expected age 31, got %v", rows[0]["age"])
	}

	n, err = eng.Exec(ctx, `DELETE FROM users WHERE id = 2`)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row deleted, got %d", n)
	}
	rows, err = eng.Query(ctx, `SELECT * FROM users`)
	if err != nil {
		t.Fatalf("select all: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row remaining, got %d", len(rows))
	}
}

func TestTransactionCommitAndRollback(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE accounts (id INT PRIMARY KEY, balance INT)`)
	mustExec(t, eng, `INSERT INTO accounts (id, balance) VALUES (1, 100)`)

	// Commit path: change should stick.
	txn, err := eng.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := txn.Exec(ctx, `UPDATE accounts SET balance = 50 WHERE id = 1`); err != nil {
		t.Fatalf("tx exec: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	rows, err := eng.Query(ctx, `SELECT * FROM accounts WHERE id = 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("select after commit: %v %v", rows, err)
	}
	if bal, _ := numeric(rows[0]["balance"]); bal != 50 {
		t.Fatalf("expected committed balance 50, got %v", rows[0]["balance"])
	}

	// Rollback path: change must be reverted.
	txn2, err := eng.Begin(ctx)
	if err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	if _, err := txn2.Exec(ctx, `UPDATE accounts SET balance = 0 WHERE id = 1`); err != nil {
		t.Fatalf("tx2 exec: %v", err)
	}
	if _, err := txn2.Exec(ctx, `INSERT INTO accounts (id, balance) VALUES (2, 999)`); err != nil {
		t.Fatalf("tx2 insert: %v", err)
	}
	if err := txn2.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	rows, err = eng.Query(ctx, `SELECT * FROM accounts WHERE id = 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("select after rollback: %v %v", rows, err)
	}
	if bal, _ := numeric(rows[0]["balance"]); bal != 50 {
		t.Fatalf("expected balance still 50 after rollback, got %v", rows[0]["balance"])
	}
	rows, err = eng.Query(ctx, `SELECT * FROM accounts WHERE id = 2`)
	if err != nil {
		t.Fatalf("select id=2 after rollback: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected inserted row to be rolled back, found %v", rows)
	}
}

func mustExec(t *testing.T, eng *Engine, query string, args ...any) {
	t.Helper()
	if _, err := eng.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

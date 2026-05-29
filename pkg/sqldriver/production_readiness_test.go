package sqldriver

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity"
)

func openProductionTestDB(t *testing.T, name string) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	DSNConfigs[path] = velocity.Config{
		Path:              path,
		DisableEncryption: true,
	}
	t.Cleanup(func() {
		delete(DSNConfigs, path)
	})
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	return db, path
}

func TestSQLDriver_ProductionPersistenceAcrossReopen(t *testing.T) {
	db, path := openProductionTestDB(t, "durable")
	if _, err := db.Exec(`CREATE TABLE accounts (id BIGINT PRIMARY KEY, email TEXT UNIQUE, balance BIGINT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id, email, balance) VALUES (?, ?, ?)`, 1, "a@example.test", 125); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	reopened, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	var email string
	var balance int
	if err := reopened.QueryRow(`SELECT email, balance FROM accounts WHERE id = ?`, 1).Scan(&email, &balance); err != nil {
		t.Fatalf("read after reopen failed: %v", err)
	}
	if email != "a@example.test" || balance != 125 {
		t.Fatalf("unexpected row after reopen: email=%q balance=%d", email, balance)
	}
}

func TestSQLDriver_ProductionPrimaryKeyAndUniqueConstraints(t *testing.T) {
	db, _ := openProductionTestDB(t, "constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "b@example.test", "Bob"); err == nil {
		t.Fatalf("expected duplicate primary key error")
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 2, "a@example.test", "Alicia"); err == nil {
		t.Fatalf("expected duplicate unique email error")
	}

	var name string
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(&name); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("duplicate insert changed original row: %q", name)
	}
}

func TestSQLDriver_ProductionNullConstraintSemantics(t *testing.T) {
	db, _ := openProductionTestDB(t, "null_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, nil, "Alice"); err != nil {
		t.Fatalf("first NULL unique insert failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 2, nil, "Bob"); err != nil {
		t.Fatalf("second NULL unique insert failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, nil, "nobody@example.test", "Nobody"); err == nil {
		t.Fatalf("expected NULL primary key insert to fail")
	}
	if _, err := db.Exec(`UPDATE users SET id = NULL WHERE id = ?`, 1); err == nil {
		t.Fatalf("expected NULL primary key update to fail")
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users WHERE email IS NULL`).Scan(&count); err != nil {
		t.Fatalf("NULL email count failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("NULL unique rows count = %d, want 2", count)
	}
}

func TestSQLDriver_ProductionNotNullConstraints(t *testing.T) {
	db, _ := openProductionTestDB(t, "not_null_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", nil); err == nil {
		t.Fatalf("expected NULL name insert to fail")
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("valid insert failed: %v", err)
	}
	if _, err := db.Exec(`UPDATE users SET name = NULL WHERE id = ?`, 1); err == nil {
		t.Fatalf("expected NULL name update to fail")
	}

	var name string
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(&name); err != nil {
		t.Fatalf("read after rejected update failed: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("rejected NOT NULL update changed row: %q", name)
	}
}

func TestSQLDriver_ProductionRejectsUnsupportedCompositeConstraints(t *testing.T) {
	db, _ := openProductionTestDB(t, "composite_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE pairs (a BIGINT, b BIGINT, PRIMARY KEY (a, b))`); err == nil {
		t.Fatalf("expected composite primary key create to fail")
	}
	if _, err := db.Exec(`CREATE TABLE unique_pairs (a BIGINT, b BIGINT, UNIQUE (a, b))`); err == nil {
		t.Fatalf("expected composite unique create to fail")
	}
}

func TestSQLDriver_ProductionMultiRowInsertEnforcesConstraints(t *testing.T) {
	db, _ := openProductionTestDB(t, "multirow_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("seed insert failed: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?), (?, ?, ?)`,
		2, "b@example.test", "Bob",
		2, "c@example.test", "Bobby"); err == nil {
		t.Fatalf("expected duplicate primary key error in multi-row insert")
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?), (?, ?, ?)`,
		3, "d@example.test", "Dana",
		4, "a@example.test", "Alicia"); err == nil {
		t.Fatalf("expected duplicate unique email error in multi-row insert")
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (5, 'e@example.test', 'Eve'), (5, 'f@example.test', 'Eva')`); err == nil {
		t.Fatalf("expected duplicate primary key error in literal multi-row insert")
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (6, 'g@example.test', 'Gail'), (7, 'g@example.test', 'Gia')`); err == nil {
		t.Fatalf("expected duplicate unique email error in literal multi-row insert")
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("failed multi-row insert left partial rows: count=%d", count)
	}
}

func TestSQLDriver_ProductionTransactionRejectsPendingConstraintDuplicates(t *testing.T) {
	db, _ := openProductionTestDB(t, "tx_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("first tx insert failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "b@example.test", "Bob"); err == nil {
		t.Fatalf("expected duplicate primary key error inside transaction")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("rollback after constraint error left %d rows", count)
	}
}

func TestSQLDriver_ProductionTransactionReadYourWritesByPrimaryKey(t *testing.T) {
	db, _ := openProductionTestDB(t, "tx_read_your_writes")
	db.SetMaxOpenConns(2)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("tx insert failed: %v", err)
	}

	var name string
	if err := tx.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(&name); err != nil {
		t.Fatalf("transaction could not read its pending insert: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("unexpected pending name: %q", name)
	}

	var outsideCount int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&outsideCount); err != nil {
		t.Fatalf("outside count failed: %v", err)
	}
	if outsideCount != 0 {
		t.Fatalf("uncommitted row leaked outside transaction: count=%d", outsideCount)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(&name); err != nil {
		t.Fatalf("read after commit failed: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("unexpected committed name: %q", name)
	}
}

func TestSQLDriver_ProductionLargeBulkClearsStaleIndexesAndRemainsQueryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large_bulk_stale_index")
	DSNConfigs[path] = velocity.Config{
		Path:              path,
		DisableEncryption: true,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"events": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true, ValueIndex: true},
					{Name: "kind", HashSearch: true},
				},
			},
		},
	}
	t.Cleanup(func() { delete(DSNConfigs, path) })

	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE events (id BIGINT PRIMARY KEY, kind TEXT, note TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO events (id, kind, note) VALUES (1, 'old', 'before bulk')`); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn failed: %v", err)
	}
	err = conn.Raw(func(raw any) error {
		c := raw.(*Conn)
		inserted, err := c.BulkInsertFuncBatchSize("events", []string{"id", "kind", "note"}, 10_001, 2_000, func(i int, dst []any) {
			id := i + 2
			dst[0] = id
			if id%2 == 0 {
				dst[1] = "even"
			} else {
				dst[1] = "odd"
			}
			dst[2] = fmt.Sprintf("event-%d", id)
		})
		if err != nil {
			return err
		}
		if inserted != 10_001 {
			return fmt.Errorf("inserted %d, want 10001", inserted)
		}
		return nil
	})
	_ = conn.Close()
	if err != nil {
		t.Fatalf("bulk insert failed: %v", err)
	}

	var evenCount int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE kind = 'even'`).Scan(&evenCount); err != nil {
		t.Fatalf("count even failed: %v", err)
	}
	if evenCount != 5001 {
		t.Fatalf("even count = %d, want 5001", evenCount)
	}
	var oldCount int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE kind = 'old'`).Scan(&oldCount); err != nil {
		t.Fatalf("count old failed: %v", err)
	}
	if oldCount != 1 {
		t.Fatalf("old count = %d, want 1", oldCount)
	}
}

func TestSQLDriver_ProductionRepeatedCloseReopenAndTransactions(t *testing.T) {
	db, path := openProductionTestDB(t, "repeated_close_reopen")
	if _, err := db.Exec(`CREATE TABLE accounts (id BIGINT PRIMARY KEY, email TEXT UNIQUE, balance BIGINT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id, email, balance) VALUES (1, 'a@example.test', 10)`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}

	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	reopened, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	tx, err := reopened.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if _, err := tx.Exec(`UPDATE accounts SET balance = balance + 5 WHERE id = 1`); err != nil {
		t.Fatalf("tx update failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO accounts (id, email, balance) VALUES (2, 'b@example.test', 20)`); err != nil {
		t.Fatalf("tx insert failed: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	var balance int
	if err := reopened.QueryRow(`SELECT balance FROM accounts WHERE id = 1`).Scan(&balance); err != nil {
		t.Fatalf("read after rollback failed: %v", err)
	}
	if balance != 10 {
		t.Fatalf("rollback balance = %d, want 10", balance)
	}

	tx, err = reopened.Begin()
	if err != nil {
		t.Fatalf("second begin failed: %v", err)
	}
	if _, err := tx.Exec(`UPDATE accounts SET balance = balance + 5 WHERE id = 1`); err != nil {
		t.Fatalf("second tx update failed: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened failed: %v", err)
	}

	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	again, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("second reopen failed: %v", err)
	}
	defer again.Close()
	if err := again.QueryRow(`SELECT balance FROM accounts WHERE id = 1`).Scan(&balance); err != nil {
		t.Fatalf("read after second reopen failed: %v", err)
	}
	if balance != 15 {
		t.Fatalf("committed balance = %d, want 15", balance)
	}
}

func TestSQLDriver_ProductionSkipCloseFlushReplaysWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skip_close_flush")
	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true, SkipCloseFlush: true}
	t.Cleanup(func() { delete(DSNConfigs, path) })

	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO items (id, name) VALUES (1, 'alpha')`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	reopened, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()
	var name string
	if err := reopened.QueryRow(`SELECT name FROM items WHERE id = 1`).Scan(&name); err != nil {
		t.Fatalf("WAL replay read failed: %v", err)
	}
	if name != "alpha" {
		t.Fatalf("name = %q, want alpha", name)
	}
}

func TestSQLDriver_ProductionTransactionScansSeePendingWritesAndDeletes(t *testing.T) {
	db, _ := openProductionTestDB(t, "tx_scan_overlay")
	db.SetMaxOpenConns(2)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("seed insert failed: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 2, "b@example.test", "Bob"); err != nil {
		t.Fatalf("tx insert failed: %v", err)
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, 1); err != nil {
		t.Fatalf("tx delete failed: %v", err)
	}

	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("tx count failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("transaction scan count = %d, want 1", count)
	}

	var name string
	if err := tx.QueryRow(`SELECT name FROM users WHERE email = ?`, "b@example.test").Scan(&name); err != nil {
		t.Fatalf("tx filtered scan missed pending insert: %v", err)
	}
	if name != "Bob" {
		t.Fatalf("unexpected pending filtered name: %q", name)
	}
	if err := tx.QueryRow(`SELECT count(*) FROM users WHERE email = ?`, "a@example.test").Scan(&count); err != nil {
		t.Fatalf("tx deleted-row count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted row visible in transaction scan: count=%d", count)
	}

	var outsideCount int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&outsideCount); err != nil {
		t.Fatalf("outside count failed: %v", err)
	}
	if outsideCount != 1 {
		t.Fatalf("outside transaction saw pending overlay: count=%d", outsideCount)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("post-commit count failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("post-commit count = %d, want 1", count)
	}
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 2).Scan(&name); err != nil {
		t.Fatalf("post-commit read failed: %v", err)
	}
	if name != "Bob" {
		t.Fatalf("unexpected committed row: %q", name)
	}
}

func TestSQLDriver_ProductionUpdateEnforcesPrimaryAndUniqueConstraints(t *testing.T) {
	db, _ := openProductionTestDB(t, "update_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("insert alice failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 2, "b@example.test", "Bob"); err != nil {
		t.Fatalf("insert bob failed: %v", err)
	}

	if _, err := db.Exec(`UPDATE users SET email = ? WHERE id = ?`, "b@example.test", 1); err == nil {
		t.Fatalf("expected duplicate unique email update to fail")
	}
	if _, err := db.Exec(`UPDATE users SET id = ? WHERE id = ?`, 3, 1); err == nil {
		t.Fatalf("expected primary key update to fail")
	}

	var email string
	if err := db.QueryRow(`SELECT email FROM users WHERE id = ?`, 1).Scan(&email); err != nil {
		t.Fatalf("read after rejected updates failed: %v", err)
	}
	if email != "a@example.test" {
		t.Fatalf("rejected update changed row: %q", email)
	}
	if _, err := db.Exec(`UPDATE users SET email = ? WHERE id = ?`, "alice@example.test", 1); err != nil {
		t.Fatalf("unique email update failed: %v", err)
	}
	if err := db.QueryRow(`SELECT email FROM users WHERE id = ?`, 1).Scan(&email); err != nil {
		t.Fatalf("read after allowed update failed: %v", err)
	}
	if email != "alice@example.test" {
		t.Fatalf("allowed update not applied: %q", email)
	}
}

func TestSQLDriver_ProductionTransactionUpdateRejectsPendingUniqueDuplicates(t *testing.T) {
	db, _ := openProductionTestDB(t, "tx_update_constraints")
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice"); err != nil {
		t.Fatalf("insert alice failed: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 2, "b@example.test", "Bob"); err != nil {
		t.Fatalf("insert bob failed: %v", err)
	}
	if _, err := tx.Exec(`UPDATE users SET email = ? WHERE id = ?`, "b@example.test", 1); err == nil {
		t.Fatalf("expected duplicate unique email update inside transaction to fail")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("rollback left rows after failed update: %d", count)
	}
}

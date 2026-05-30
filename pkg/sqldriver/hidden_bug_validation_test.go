package sqldriver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSQLDriver_ProductionQueryCacheConnPutDeleteInvalidation(t *testing.T) {
	db, _ := openProductionTestDB(t, "cache_conn_put_delete")
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30), (2, 'Bob', 40)`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	const pointSQL = `SELECT name FROM users WHERE id = ?`
	var name string
	if err := db.QueryRow(pointSQL, 1).Scan(&name); err != nil {
		t.Fatalf("warm point query failed: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("name=%q, want Alice", name)
	}

	pointKey := queryCacheKey(pointSQL, []driver.NamedValue{{Ordinal: 1, Value: 1}}, false)
	withValidationRawConn(t, db, func(c *Conn) error {
		if _, ok := c.queryCache.Get(pointKey); !ok {
			return fmt.Errorf("point query was not cached before raw put")
		}
		return c.Put([]byte("users:1"), []byte(`{"id":1,"name":"Alicia","age":31}`))
	})

	if err := db.QueryRow(pointSQL, 1).Scan(&name); err != nil {
		t.Fatalf("point query after raw put failed: %v", err)
	}
	if name != "Alicia" {
		t.Fatalf("stale point cache after raw put: got %q, want Alicia", name)
	}

	const countSQL = `SELECT count(*) FROM users`
	var count int
	if err := db.QueryRow(countSQL).Scan(&count); err != nil {
		t.Fatalf("warm count query failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("count=%d, want 2", count)
	}
	countKey := queryCacheKey(countSQL, nil, false)
	withValidationRawConn(t, db, func(c *Conn) error {
		if _, ok := c.queryCache.Get(countKey); !ok {
			return fmt.Errorf("count query was not cached before raw delete")
		}
		return c.Delete([]byte("users:2"))
	})

	if err := db.QueryRow(countSQL).Scan(&count); err != nil {
		t.Fatalf("count query after raw delete failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("stale table cache after raw delete: count=%d, want 1", count)
	}
}

func TestSQLDriver_ProductionQueryCacheSchemaAndReopenInvalidation(t *testing.T) {
	db, path := openProductionTestDB(t, "cache_schema_reopen")
	if _, err := db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create users failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, name) VALUES (1, 'Alice')`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(new(string)); err != nil {
		t.Fatalf("warm select failed: %v", err)
	}
	withValidationRawConn(t, db, func(c *Conn) error {
		if len(c.queryCache.items) == 0 {
			return fmt.Errorf("expected warmed cache before schema change")
		}
		return nil
	})

	if _, err := db.Exec(`CREATE TABLE audit (id BIGINT PRIMARY KEY, note TEXT)`); err != nil {
		t.Fatalf("create audit failed: %v", err)
	}
	withValidationRawConn(t, db, func(c *Conn) error {
		if len(c.queryCache.items) != 0 {
			if _, ok := c.queryCache.Get(queryCacheKey(`SELECT name FROM users WHERE id = ?`, []driver.NamedValue{{Ordinal: 1, Value: 1}}, false)); ok {
				return fmt.Errorf("schema change left old cached select valid")
			}
		}
		return nil
	})

	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	reopened, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()
	withValidationRawConn(t, reopened, func(c *Conn) error {
		if len(c.queryCache.items) != 0 {
			return fmt.Errorf("reopen reused stale in-memory query cache")
		}
		return nil
	})
}

func TestSQLDriver_ProductionRowLocksHonorContextCancellation(t *testing.T) {
	locks := newRowLockManager()
	unlock, err := locks.acquire(context.Background(), []string{"users:1"})
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = locks.acquire(ctx, []string{"users:1"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked acquire error=%v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("row lock ignored context for %v", elapsed)
	}
}

func TestSQLDriver_ProductionLargeTransactionRollbackDoesNotLeakAutoFlush(t *testing.T) {
	db, _ := openProductionTestDB(t, "large_tx_rollback_no_leak")
	defer db.Close()

	withValidationRawConn(t, db, func(c *Conn) error {
		tx, err := c.BeginTx(context.Background(), driver.TxOptions{})
		if err != nil {
			return err
		}
		for i := 0; i < 66_000; i++ {
			key := []byte(fmt.Sprintf("txleak:%05d", i))
			if err := c.Put(key, []byte(`{"ok":true}`)); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Rollback(); err != nil {
			return err
		}
		for _, key := range [][]byte{[]byte("txleak:00000"), []byte("txleak:65535"), []byte("txleak:65999")} {
			if _, err := c.db.Get(key); err == nil {
				return fmt.Errorf("rolled-back large transaction leaked key %s", key)
			}
		}
		return nil
	})
}

func withValidationRawConn(t *testing.T, db *sql.DB, fn func(*Conn) error) {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn failed: %v", err)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		c, ok := raw.(*Conn)
		if !ok {
			return fmt.Errorf("raw conn has type %T", raw)
		}
		return fn(c)
	}); err != nil {
		t.Fatal(err)
	}
}

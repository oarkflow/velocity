//go:build million

package sqldriver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_MillionRowComplexWorkload(t *testing.T) {
	rowCount := envInt("VELOCITY_SQL_MILLION_ROWS", 1_000_000)
	chunkSize := envInt("VELOCITY_SQL_MILLION_CHUNK", 50_000)
	if rowCount < 10_000 {
		t.Fatalf("VELOCITY_SQL_MILLION_ROWS=%d is too small for the million-row workload", rowCount)
	}
	if chunkSize <= 0 {
		chunkSize = 50_000
	}

	path := filepath.Join(t.TempDir(), "million_sql")
	db := openMillionWorkloadDB(t, path)
	defer db.Close()

	for _, stmt := range millionSchemaSQL() {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("schema exec failed: %v", err)
		}
	}

	start := time.Now()
	usersStart := time.Now()
	bulkInsertUsers(t, db, rowCount, chunkSize)
	t.Logf("loaded %d users in %s", rowCount, time.Since(usersStart))
	orderCount := rowCount / 2
	ordersStart := time.Now()
	bulkInsertOrders(t, db, orderCount, rowCount, chunkSize)
	t.Logf("loaded %d orders in %s", orderCount, time.Since(ordersStart))
	t.Logf("loaded %d users and %d orders in %s", rowCount, orderCount, time.Since(start))

	var name string
	var region string
	var spend float64
	pointID := rowCount*3/4 + 1
	timedTestStep(t, "point lookup", func() {
		if err := db.QueryRow("SELECT name, region, spend FROM users WHERE id = ?", pointID).Scan(&name, &region, &spend); err != nil {
			t.Fatalf("point lookup failed: %v", err)
		}
	})
	if want := fmt.Sprintf("user-%07d", pointID); name != want {
		t.Fatalf("point lookup name = %q, want %q", name, want)
	}

	timedTestStep(t, "cte correlated exists", func() {
		assertCount(t, db, `
			WITH sample_order AS (
				SELECT id FROM orders WHERE id = 50 AND status = 'paid' AND total >= 100
			)
			SELECT COUNT(*)
			FROM users u
			WHERE u.id = 50 AND active = 1
			  AND EXISTS (
				SELECT id FROM sample_order so WHERE so.id = u.id
			)
		`, 1)
	})

	timedTestStep(t, "bounded cte join", func() {
		rows, err := db.Query(`
			WITH sample_user AS (
				SELECT id, region, spend FROM users WHERE id = 50
			), sample_order AS (
				SELECT user_id, total FROM orders WHERE id = 50
			)
			SELECT su.region, su.spend, so.total
			FROM sample_user su
			JOIN sample_order so ON so.user_id = su.id
		`)
		if err != nil {
			t.Fatalf("bounded CTE join query failed: %v", err)
		}
		joinedRows := 0
		for rows.Next() {
			var gotRegion string
			var spend float64
			var total float64
			if err := rows.Scan(&gotRegion, &spend, &total); err != nil {
				t.Fatalf("bounded join scan failed: %v", err)
			}
			if gotRegion == "" || spend <= 0 || total <= 0 {
				t.Fatalf("invalid bounded join row: region=%q spend=%v total=%v", gotRegion, spend, total)
			}
			joinedRows++
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("bounded join rows failed: %v", err)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("bounded join rows close failed: %v", err)
		}
		if joinedRows != 1 {
			t.Fatalf("bounded join rows = %d, want 1", joinedRows)
		}
	})

	if _, err := db.Exec(`
		CREATE VIEW sample_users_view AS
		SELECT id, region, active
		FROM users
		WHERE id = 50
	`); err != nil {
		t.Fatalf("create view failed: %v", err)
	}
	timedTestStep(t, "view count", func() {
		assertCount(t, db, "SELECT COUNT(*) FROM sample_users_view", 1)
	})

	timedTestStep(t, "update first 100 users", func() {
		if _, err := db.Exec("UPDATE users SET spend = spend + 10 WHERE id <= 100"); err != nil {
			t.Fatalf("update failed: %v", err)
		}
	})
	timedTestStep(t, "delete first 100 orders", func() {
		if _, err := db.Exec("DELETE FROM orders WHERE id <= 100"); err != nil {
			t.Fatalf("delete failed: %v", err)
		}
	})
	timedTestStep(t, "count orders after delete", func() {
		assertCount(t, db, "SELECT COUNT(*) FROM orders", orderCount-100)
	})

	if err := db.Close(); err != nil {
		t.Fatalf("close before reopen failed: %v", err)
	}
	db = openMillionWorkloadDB(t, path)
	defer db.Close()
	timedTestStep(t, "reopen count users", func() {
		assertCount(t, db, "SELECT COUNT(*) FROM users", rowCount)
	})
	timedTestStep(t, "reopen count orders", func() {
		assertCount(t, db, "SELECT COUNT(*) FROM orders", orderCount-100)
	})
	timedTestStep(t, "reopen count view", func() {
		assertCount(t, db, "SELECT COUNT(*) FROM sample_users_view", 1)
	})
}

var millionRegions = []string{"north", "south", "east", "west", "central"}

func openMillionWorkloadDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	DSNConfigs[path] = velocity.Config{
		Path:              path,
		PerformanceMode:   "performance",
		DisableEncryption: true,
		DisableFsync:      true,
		SkipCloseFlush:    true,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true, ValueIndex: true},
					{Name: "region", HashSearch: true},
					{Name: "active", HashSearch: true},
					{Name: "spend", ValueIndex: true},
				},
			},
			"orders": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true, ValueIndex: true},
					{Name: "user_id", HashSearch: true, ValueIndex: true},
					{Name: "region", HashSearch: true},
					{Name: "status", HashSearch: true},
					{Name: "total", ValueIndex: true},
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
	return db
}

func millionSchemaSQL() []string {
	return []string{
		`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, age BIGINT, region TEXT, spend BIGINT, active BIGINT)`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, region TEXT, total BIGINT, status TEXT)`,
	}
}

func bulkInsertUsers(t *testing.T, db *sql.DB, total int, chunk int) {
	t.Helper()
	withRawConn(t, db, func(conn *Conn) {
		inserted, err := conn.BulkInsertFuncBatchSize("users", []string{"id", "name", "age", "region", "spend", "active"}, total, chunk, func(i int, dst []any) {
			if i > 0 && i%100_000 == 0 {
				t.Logf("prepared %d/%d users", i, total)
			}
			id := i + 1
			dst[0] = id
			dst[1] = fmt.Sprintf("user-%07d", id)
			dst[2] = 18 + (id % 63)
			dst[3] = millionRegions[id%len(millionRegions)]
			dst[4] = 100 + (id % 10_000)
			dst[5] = activeFlag(id)
		})
		if err != nil {
			t.Fatalf("bulk users failed after %d inserts: %v", inserted, err)
		}
		if inserted != int64(total) {
			t.Fatalf("bulk users inserted %d, want %d", inserted, total)
		}
	})
}

func bulkInsertOrders(t *testing.T, db *sql.DB, total int, userCount int, chunk int) {
	t.Helper()
	withRawConn(t, db, func(conn *Conn) {
		inserted, err := conn.BulkInsertFuncBatchSize("orders", []string{"id", "user_id", "region", "total", "status"}, total, chunk, func(i int, dst []any) {
			if i > 0 && i%100_000 == 0 {
				t.Logf("prepared %d/%d orders", i, total)
			}
			id := i + 1
			userID := ((id - 1) % userCount) + 1
			dst[0] = id
			dst[1] = userID
			dst[2] = millionRegions[userID%len(millionRegions)]
			dst[3] = 50 + (id % 500)
			if id%3 == 0 {
				dst[4] = "open"
			} else {
				dst[4] = "paid"
			}
		})
		if err != nil {
			t.Fatalf("bulk orders failed after %d inserts: %v", inserted, err)
		}
		if inserted != int64(total) {
			t.Fatalf("bulk orders inserted %d, want %d", inserted, total)
		}
	})
}

func withRawConn(t *testing.T, db *sql.DB, fn func(*Conn)) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn failed: %v", err)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		velocityConn, ok := raw.(*Conn)
		if !ok {
			return fmt.Errorf("unexpected raw connection %T", raw)
		}
		fn(velocityConn)
		return nil
	}); err != nil {
		t.Fatalf("raw conn failed: %v", err)
	}
}

func assertCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("count query failed: %v\nquery:\n%s", err, query)
	}
	if got != want {
		t.Fatalf("count query returned %d, want %d\nquery:\n%s", got, want, query)
	}
}

func countPaidOrderUsers(orderCount int, limit int) int {
	count := 0
	maxID := minInt(orderCount, limit)
	for id := 1; id <= maxID; id++ {
		if id%3 == 0 {
			continue
		}
		if activeFlag(id) != 1 {
			continue
		}
		if 50+(id%500) < 100 {
			continue
		}
		count++
	}
	return count
}

func activeFlag(id int) int {
	if id%4 == 0 {
		return 0
	}
	return 1
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func timedTestStep(t *testing.T, name string, fn func()) {
	t.Helper()
	start := time.Now()
	fn()
	t.Logf("%s took %s", name, time.Since(start))
}

var _ driver.Conn = (*Conn)(nil)

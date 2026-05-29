package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

var regions = []string{"north", "south", "east", "west", "central"}

func main() {
	rows := envInt("VELOCITY_SQL_MILLION_ROWS", 1_000_000)
	chunk := envInt("VELOCITY_SQL_MILLION_CHUNK", 50_000)
	path := os.Getenv("VELOCITY_SQL_MILLION_PATH")
	if path == "" {
		path = filepath.Join(os.TempDir(), "velocity_sql_million_demo")
	}
	if os.Getenv("VELOCITY_SQL_MILLION_KEEP") != "1" {
		if err := os.RemoveAll(path); err != nil {
			log.Fatalf("remove old demo db: %v", err)
		}
		defer os.RemoveAll(path)
	}

	db := openDB(path)
	defer db.Close()

	timed("create schema", func() {
		mustExec(db, `CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, age BIGINT, region TEXT, spend BIGINT, active BIGINT)`)
		mustExec(db, `CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, region TEXT, total BIGINT, status TEXT)`)
	})

	timed(fmt.Sprintf("bulk insert %d users", rows), func() {
		bulkInsertUsers(db, rows, chunk)
	})
	orderCount := rows / 2
	timed(fmt.Sprintf("bulk insert %d orders", orderCount), func() {
		bulkInsertOrders(db, orderCount, rows, chunk)
	})

	timed("count users", func() {
		fmt.Printf("users: %d\n", mustCount(db, "SELECT COUNT(*) FROM users"))
	})
	timed("point lookup", func() {
		id := rows*3/4 + 1
		var name string
		var region string
		var spend float64
		must(db.QueryRow("SELECT name, region, spend FROM users WHERE id = ?", id).Scan(&name, &region, &spend))
		fmt.Printf("point id=%d name=%s region=%s spend=%.0f\n", id, name, region, spend)
	})
	timed("cte + correlated exists", func() {
		count := mustCount(db, `
			WITH sample_order AS (
				SELECT id FROM orders WHERE id = 50 AND status = 'paid' AND total >= 100
			)
			SELECT COUNT(*)
			FROM users u
			WHERE u.id = 50 AND active = 1
			  AND EXISTS (
				SELECT id FROM sample_order so WHERE so.id = u.id
			)
		`)
		fmt.Printf("active users with paid orders: %d\n", count)
	})
	timed("bounded cte join", func() {
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
		must(err)
		for rows.Next() {
			var region string
			var spend float64
			var total float64
			must(rows.Scan(&region, &spend, &total))
			fmt.Printf("%-7s spend=%.0f order_total=%.0f\n", region, spend, total)
		}
		must(rows.Err())
		must(rows.Close())
	})
	timed("view + reopen", func() {
		mustExec(db, `
			CREATE VIEW sample_users_view AS
			SELECT id, region, active
			FROM users
			WHERE id = 50
		`)
		fmt.Printf("view rows before reopen: %d\n", mustCount(db, "SELECT COUNT(*) FROM sample_users_view"))
		must(db.Close())
		db = openDB(path)
		fmt.Printf("users after reopen: %d\n", mustCount(db, "SELECT COUNT(*) FROM users"))
		fmt.Printf("view rows after reopen: %d\n", mustCount(db, "SELECT COUNT(*) FROM sample_users_view"))
	})
}

func openDB(path string) *sql.DB {
	sqldriver.DSNConfigs[path] = velocity.Config{
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
	db, err := sql.Open(sqldriver.DriverName, path)
	must(err)
	return db
}

func bulkInsertUsers(db *sql.DB, total int, chunk int) {
	withRawConn(db, func(conn *sqldriver.Conn) {
		_, err := conn.BulkInsertFuncBatchSize("users", []string{"id", "name", "age", "region", "spend", "active"}, total, chunk, func(i int, dst []any) {
			id := i + 1
			dst[0] = id
			dst[1] = fmt.Sprintf("user-%07d", id)
			dst[2] = 18 + (id % 63)
			dst[3] = regions[id%len(regions)]
			dst[4] = 100 + (id % 10_000)
			dst[5] = activeFlag(id)
		})
		must(err)
	})
}

func bulkInsertOrders(db *sql.DB, total int, userCount int, chunk int) {
	withRawConn(db, func(conn *sqldriver.Conn) {
		_, err := conn.BulkInsertFuncBatchSize("orders", []string{"id", "user_id", "region", "total", "status"}, total, chunk, func(i int, dst []any) {
			id := i + 1
			userID := ((id - 1) % userCount) + 1
			dst[0] = id
			dst[1] = userID
			dst[2] = regions[userID%len(regions)]
			dst[3] = 50 + (id % 500)
			if id%3 == 0 {
				dst[4] = "open"
			} else {
				dst[4] = "paid"
			}
		})
		must(err)
	})
}

func withRawConn(db *sql.DB, fn func(*sqldriver.Conn)) {
	conn, err := db.Conn(context.Background())
	must(err)
	defer conn.Close()
	must(conn.Raw(func(raw any) error {
		velocityConn, ok := raw.(*sqldriver.Conn)
		if !ok {
			return fmt.Errorf("unexpected raw connection %T", raw)
		}
		fn(velocityConn)
		return nil
	}))
}

func timed(label string, fn func()) {
	start := time.Now()
	fn()
	fmt.Printf("%s took %s\n", label, time.Since(start).Round(time.Millisecond))
}

func mustExec(db *sql.DB, query string) {
	_, err := db.Exec(query)
	must(err)
}

func mustCount(db *sql.DB, query string) int {
	var count int
	must(db.QueryRow(query).Scan(&count))
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

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

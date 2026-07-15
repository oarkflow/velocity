package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

type encDisabledBench struct {
	name string
	db   *sql.DB
	path string
}

func openEncDisabledVelocitySQL(b *testing.B, name string) encDisabledBench {
	b.Helper()
	path := filepath.Join(b.TempDir(), name)
	sqldriver.DSNConfigs[path] = velocity.Config{
		Path:                    path,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		DisableIndexPersistence: true,
		PerformanceMode:         "performance",
		SQLQueryCacheDisabled:   false,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "age", ValueIndex: true},
				},
			},
			"orders": {
				Fields: []velocity.SearchSchemaField{
					{Name: "id", HashSearch: true},
					{Name: "user_id", HashSearch: true},
				},
			},
		},
	}
	db, err := sql.Open(sqldriver.DriverName, path)
	if err != nil {
		b.Fatal(err)
	}
	return encDisabledBench{name: name, db: db, path: path}
}

func (e *encDisabledBench) cleanup() {
	_ = e.db.Close()
	delete(sqldriver.DSNConfigs, e.path)
	_ = os.RemoveAll(e.path)
}

func openEncDisabledSQLite(b *testing.B) encDisabledBench {
	b.Helper()
	path := filepath.Join(b.TempDir(), "sqlite_enc_disabled.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		b.Fatal(err)
	}
	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA temp_store = MEMORY`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			b.Fatal(err)
		}
	}
	return encDisabledBench{name: "SQLite", db: db, path: path}
}

func openEncDisabledPostgres(b *testing.B, dsn string) encDisabledBench {
	b.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		b.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		b.Skipf("postgres unavailable: %v", err)
	}
	return encDisabledBench{name: "Postgres", db: db, path: ""}
}

func seedEncDisabled(b *testing.B, db *sql.DB, placeholder string, users int, orders int) {
	b.Helper()
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS orders`,
		`DROP TABLE IF EXISTS users`,
		`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`,
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total BIGINT)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			b.Fatal(err)
		}
	}
	for _, stmt := range []string{
		`CREATE INDEX idx_users_age ON users (age)`,
		`CREATE INDEX idx_orders_user_id ON orders (user_id)`,
	} {
		_, _ = db.Exec(stmt)
	}

	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	query := `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`
	if placeholder == "$" {
		query = `INSERT INTO users (id, name, age) VALUES ($1, $2, $3)`
	}
	stmt, err := tx.Prepare(query)
	if err != nil {
		_ = tx.Rollback()
		b.Fatal(err)
	}
	defer stmt.Close()
	for i := 1; i <= users; i++ {
		if _, err := stmt.Exec(i, fmt.Sprintf("user_%d", i), 20+(i%50)); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}

	tx2, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	oquery := `INSERT INTO orders (id, user_id, total) VALUES (?, ?, ?)`
	if placeholder == "$" {
		oquery = `INSERT INTO orders (id, user_id, total) VALUES ($1, $2, $3)`
	}
	ostmt, err := tx2.Prepare(oquery)
	if err != nil {
		_ = tx2.Rollback()
		b.Fatal(err)
	}
	defer ostmt.Close()
	for i := 1; i <= orders; i++ {
		if _, err := ostmt.Exec(i, (i%users)+1, i%100); err != nil {
			_ = tx2.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx2.Commit(); err != nil {
		b.Fatal(err)
	}
}

func batchInsertEncDisabled(b *testing.B, db *sql.DB, placeholder string, startID int, count int) {
	b.Helper()
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	query := `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`
	if placeholder == "$" {
		query = `INSERT INTO users (id, name, age) VALUES ($1, $2, $3)`
	}
	stmt, err := tx.Prepare(query)
	if err != nil {
		_ = tx.Rollback()
		b.Fatal(err)
	}
	defer stmt.Close()
	for i := 0; i < count; i++ {
		id := startID + i
		if _, err := stmt.Exec(id, fmt.Sprintf("user_%d", id), 20+(id%50)); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkEncDisabledSQL runs all SQL benchmarks with encryption disabled
func BenchmarkEncDisabledSQL(b *testing.B) {
	providers := []encDisabledBench{
		openEncDisabledVelocitySQL(b, "VelocitySQL_CacheEnabled"),
		openEncDisabledVelocitySQL(b, "VelocitySQL_CacheDisabled"),
		openEncDisabledSQLite(b),
	}
	if dsn := os.Getenv("VELOCITY_BENCH_POSTGRES_DSN"); dsn != "" {
		providers = append(providers, openEncDisabledPostgres(b, dsn))
	}

	for _, p := range providers {
		b.Run(p.name, func(b *testing.B) {
			defer p.cleanup()
			ph := "?"
			if p.name == "Postgres" {
				ph = "$"
			}
			seedEncDisabled(b, p.db, ph, 5000, 1000)

			b.Run("PointReadPrepared", func(b *testing.B) {
				q := `SELECT name, age FROM users WHERE id = ?`
				if ph == "$" {
					q = `SELECT name, age FROM users WHERE id = $1`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				var name string
				var age int
				if err := stmt.QueryRow(100).Scan(&name, &age); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(0)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := stmt.QueryRow(100).Scan(&name, &age); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("CountPrepared", func(b *testing.B) {
				q := `SELECT count(*) FROM users WHERE age >= ?`
				if ph == "$" {
					q = `SELECT count(*) FROM users WHERE age >= $1`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				var count int
				if err := stmt.QueryRow(40).Scan(&count); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := stmt.QueryRow(40).Scan(&count); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("FilteredScanPrepared", func(b *testing.B) {
				q := `SELECT id, name, age FROM users WHERE age = ? ORDER BY id LIMIT 20`
				if ph == "$" {
					q = `SELECT id, name, age FROM users WHERE age = $1 ORDER BY id LIMIT 20`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				rows, err := stmt.Query(40)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
					var id int
					var name string
					var age int
					_ = rows.Scan(&id, &name, &age)
				}
				_ = rows.Close()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					rows, err := stmt.Query(40)
					if err != nil {
						b.Fatal(err)
					}
					for rows.Next() {
						var id int
						var name string
						var age int
						_ = rows.Scan(&id, &name, &age)
					}
					_ = rows.Close()
				}
			})

			b.Run("JoinPrepared", func(b *testing.B) {
				q := `SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.id = ?`
				if ph == "$" {
					q = `SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.id = $1`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				var name string
				var total int
				if err := stmt.QueryRow(500).Scan(&name, &total); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := stmt.QueryRow(500).Scan(&name, &total); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("SingleInsertPrepared", func(b *testing.B) {
				q := `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`
				if ph == "$" {
					q = `INSERT INTO users (id, name, age) VALUES ($1, $2, $3)`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				start := int(time.Now().UnixNano() % 1_000_000_000)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					id := start + i
					if _, err := stmt.Exec(id, fmt.Sprintf("bench_user_%d", id), 20+(id%50)); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("BatchInsertTx1000", func(b *testing.B) {
				start := int(time.Now().UnixNano() % 1_000_000_000)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					batchInsertEncDisabled(b, p.db, ph, start+(i*1000), 1000)
				}
			})

			b.Run("BulkInsertTx5000", func(b *testing.B) {
				start := int(time.Now().UnixNano() % 1_000_000_000)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					batchInsertEncDisabled(b, p.db, ph, start+(i*5000), 5000)
				}
			})

			b.Run("UpdatePrepared", func(b *testing.B) {
				q := `UPDATE users SET age = ? WHERE id = ?`
				if ph == "$" {
					q = `UPDATE users SET age = $1 WHERE id = $2`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					id := (i % 5000) + 1
					if _, err := stmt.Exec(25+i%30, id); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("DeletePrepared", func(b *testing.B) {
				q := `DELETE FROM users WHERE id = ?`
				if ph == "$" {
					q = `DELETE FROM users WHERE id = $1`
				}
				stmt, err := p.db.Prepare(q)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					id := (i % 5000) + 1
					if _, err := stmt.Exec(id); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkEncDisabledKV benchmarks native Velocity KV with encryption disabled
func BenchmarkEncDisabledKV(b *testing.B) {
	ctx := context.Background()
	path := filepath.Join(b.TempDir(), "velocity_kv_enc_disabled")
	defer os.RemoveAll(path)

	cfg := velocity.Config{
		Path:                    path,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		DisableIndexPersistence: true,
		PerformanceMode:         "performance",
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "email", HashSearch: true},
					{Name: "age", ValueIndex: true},
				},
			},
		},
	}
	db, err := velocity.NewWithConfig(cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	_ = ctx

	b.Run("Put", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := i + 1
			key := []byte(fmt.Sprintf("users:%d", id))
			data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
			if err := db.Put(key, data); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Get", func(b *testing.B) {
		seed := 100000
		for i := 0; i < seed; i++ {
			id := i + 1
			key := []byte(fmt.Sprintf("users:%d", id))
			data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
			if err := db.Put(key, data); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := (i % seed) + 1
			key := []byte(fmt.Sprintf("users:%d", id))
			if _, err := db.Get(key); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("BatchPut1000", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			batch := db.NewBatchWriter(1000)
			for j := 0; j < 1000; j++ {
				id := i*1000 + j + 200000
				key := []byte(fmt.Sprintf("users:%d", id))
				data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
				if err := batch.Put(key, data); err != nil {
					b.Fatal(err)
				}
			}
			if err := batch.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SearchCount", func(b *testing.B) {
		seed := 50000
		for i := 0; i < seed; i++ {
			id := i + 300000
			key := []byte(fmt.Sprintf("users:%d", id))
			data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
			if err := db.Put(key, data); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := db.SearchCount(velocity.SearchQuery{
				Prefix: "users",
				Filters: []velocity.SearchFilter{
					{Field: "age", Op: ">=", Value: 30},
				},
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

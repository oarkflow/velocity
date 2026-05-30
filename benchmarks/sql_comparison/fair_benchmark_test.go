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

func BenchmarkFairSQLComparison(b *testing.B) {
	for _, provider := range fairSQLProviders(b) {
		b.Run(provider.name, func(b *testing.B) {
			defer provider.cleanup()
			seedFairSQL(b, provider.db, provider.placeholder, 5000, 1000)

			b.Run("PointReadWarmPrepared", func(b *testing.B) {
				stmt, err := provider.db.Prepare(`SELECT name, age FROM users WHERE id = ?`)
				if provider.placeholder == "$" {
					stmt, err = provider.db.Prepare(`SELECT name, age FROM users WHERE id = $1`)
				}
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				var name string
				var age int
				if err := stmt.QueryRow(100).Scan(&name, &age); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := stmt.QueryRow(100).Scan(&name, &age); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("CountWarmPrepared", func(b *testing.B) {
				stmt, err := provider.db.Prepare(`SELECT count(*) FROM users WHERE age >= ?`)
				if provider.placeholder == "$" {
					stmt, err = provider.db.Prepare(`SELECT count(*) FROM users WHERE age >= $1`)
				}
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

			b.Run("FilteredScanWarmPrepared", func(b *testing.B) {
				query := `SELECT id, name, age FROM users WHERE age = ? ORDER BY id LIMIT 20`
				if provider.placeholder == "$" {
					query = `SELECT id, name, age FROM users WHERE age = $1 ORDER BY id LIMIT 20`
				}
				stmt, err := provider.db.Prepare(query)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				warmRows, err := stmt.Query(40)
				if err != nil {
					b.Fatal(err)
				}
				for warmRows.Next() {
					var id int
					var name string
					var age int
					if err := warmRows.Scan(&id, &name, &age); err != nil {
						_ = warmRows.Close()
						b.Fatal(err)
					}
				}
				if err := warmRows.Err(); err != nil {
					_ = warmRows.Close()
					b.Fatal(err)
				}
				_ = warmRows.Close()
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
						if err := rows.Scan(&id, &name, &age); err != nil {
							_ = rows.Close()
							b.Fatal(err)
						}
					}
					if err := rows.Err(); err != nil {
						_ = rows.Close()
						b.Fatal(err)
					}
					_ = rows.Close()
				}
			})

			b.Run("JoinWarmPrepared", func(b *testing.B) {
				query := `SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.id = ?`
				if provider.placeholder == "$" {
					query = `SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.id = $1`
				}
				stmt, err := provider.db.Prepare(query)
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
				query := `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`
				if provider.placeholder == "$" {
					query = `INSERT INTO users (id, name, age) VALUES ($1, $2, $3)`
				}
				stmt, err := provider.db.Prepare(query)
				if err != nil {
					b.Fatal(err)
				}
				defer stmt.Close()
				start := int(time.Now().UnixNano() % 1_000_000_000)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					id := start + i
					if _, err := stmt.Exec(id, fmt.Sprintf("insert_user_%d", id), 20+(id%50)); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("BatchInsertTx1000", func(b *testing.B) {
				start := int(time.Now().UnixNano() % 1_000_000_000)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					insertFairSQLBatch(b, provider.db, provider.placeholder, start+(i*1000), 1000)
				}
			})
		})
	}
}

func BenchmarkFairKVComparison(b *testing.B) {
	ctx := context.Background()
	for _, provider := range []DBProvider{
		NewVelocityProvider(filepath.Join(b.TempDir(), "velocity_native"), false),
		NewYogaDBProvider(filepath.Join(b.TempDir(), "yogadb")),
	} {
		b.Run(provider.Name(), func(b *testing.B) {
			if err := provider.Setup(ctx); err != nil {
				b.Skipf("setup failed: %v", err)
			}
			defer provider.Cleanup(ctx)
			if err := provider.BatchInsert(ctx, 1, 5000); err != nil {
				b.Fatalf("seed failed: %v", err)
			}
			b.Run("PointReadWarm", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, _, err := provider.Read(ctx, 100); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("SearchCountWarm", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := provider.Search(ctx, 40); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("BatchInsert1000", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := provider.BatchInsert(ctx, 10_000_000+(i*1000), 1000); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

type fairSQLProvider struct {
	name        string
	db          *sql.DB
	cleanup     func()
	placeholder string
}

func fairSQLProviders(b *testing.B) []fairSQLProvider {
	b.Helper()
	providers := []fairSQLProvider{
		openFairVelocitySQL(b, "VelocitySQLCached", false),
		openFairVelocitySQL(b, "VelocitySQLNoCache", true),
		openFairSQLite(b),
	}
	if dsn := os.Getenv("VELOCITY_BENCH_POSTGRES_DSN"); dsn != "" {
		providers = append(providers, openFairPostgres(b, dsn))
	}
	return providers
}

func openFairVelocitySQL(b *testing.B, name string, cacheDisabled bool) fairSQLProvider {
	b.Helper()
	path := filepath.Join(b.TempDir(), name)
	sqldriver.DSNConfigs[path] = velocity.Config{
		Path:                    path,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		DisableIndexPersistence: true,
		PerformanceMode:         "performance",
		SQLQueryCacheDisabled:   cacheDisabled,
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
	return fairSQLProvider{
		name: name,
		db:   db,
		cleanup: func() {
			_ = db.Close()
			delete(sqldriver.DSNConfigs, path)
			_ = os.RemoveAll(path)
		},
	}
}

func openFairSQLite(b *testing.B) fairSQLProvider {
	b.Helper()
	path := filepath.Join(b.TempDir(), "sqlite.db")
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
	return fairSQLProvider{name: "SQLite", db: db, cleanup: func() { _ = db.Close() }}
}

func openFairPostgres(b *testing.B, dsn string) fairSQLProvider {
	b.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		b.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		b.Skipf("postgres unavailable: %v", err)
	}
	return fairSQLProvider{name: "Postgres", db: db, cleanup: func() { _ = db.Close() }, placeholder: "$"}
}

func seedFairSQL(b *testing.B, db *sql.DB, placeholder string, users int, orders int) {
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
	insertFairSQLBatch(b, db, placeholder, 1, users)
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	query := `INSERT INTO orders (id, user_id, total) VALUES (?, ?, ?)`
	if placeholder == "$" {
		query = `INSERT INTO orders (id, user_id, total) VALUES ($1, $2, $3)`
	}
	stmt, err := tx.Prepare(query)
	if err != nil {
		_ = tx.Rollback()
		b.Fatal(err)
	}
	defer stmt.Close()
	for i := 1; i <= orders; i++ {
		if _, err := stmt.Exec(i, (i%users)+1, i%100); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

func insertFairSQLBatch(b *testing.B, db *sql.DB, placeholder string, startID int, count int) {
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

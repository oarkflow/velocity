package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

type sbsConfig struct {
	name        string
	open        func(b *testing.B, dir string) (*sql.DB, func())
	placeholder string
}

func sbsProviders(b *testing.B) []sbsConfig {
	b.Helper()
	var providers []sbsConfig

	providers = append(providers, sbsConfig{
		name: "VelocitySQL_Cached",
		open: func(b *testing.B, dir string) (*sql.DB, func()) {
			path := filepath.Join(dir, "vsql_cached")
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
			return db, func() {
				db.Close()
				delete(sqldriver.DSNConfigs, path)
				os.RemoveAll(path)
			}
		},
		placeholder: "?",
	})

	providers = append(providers, sbsConfig{
		name: "VelocitySQL_NoCache",
		open: func(b *testing.B, dir string) (*sql.DB, func()) {
			path := filepath.Join(dir, "vsql_nocache")
			sqldriver.DSNConfigs[path] = velocity.Config{
				Path:                    path,
				DisableEncryption:       true,
				DisableWAL:              true,
				DisableFsync:            true,
				DisableIndexPersistence: true,
				PerformanceMode:         "performance",
				SQLQueryCacheDisabled:   true,
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
			return db, func() {
				db.Close()
				delete(sqldriver.DSNConfigs, path)
				os.RemoveAll(path)
			}
		},
		placeholder: "?",
	})

	providers = append(providers, sbsConfig{
		name: "SQLite",
		open: func(b *testing.B, dir string) (*sql.DB, func()) {
			path := filepath.Join(dir, "sqlite.db")
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
					db.Close()
					b.Fatal(err)
				}
			}
			return db, func() { db.Close() }
		},
		placeholder: "?",
	})

	return providers
}

func sbsSeed(b *testing.B, db *sql.DB, ph string, users, orders int) {
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
	for _, idx := range []string{
		`CREATE INDEX idx_users_age ON users (age)`,
		`CREATE INDEX idx_orders_user_id ON orders (user_id)`,
	} {
		_, _ = db.Exec(idx)
	}
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	q := fmt.Sprintf(`INSERT INTO users (id, name, age) VALUES (%s, %s, %s)`, ph, ph, ph)
	stmt, err := tx.Prepare(q)
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
	oq := fmt.Sprintf(`INSERT INTO orders (id, user_id, total) VALUES (%s, %s, %s)`, ph, ph, ph)
	ostmt, err := tx2.Prepare(oq)
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

func sbsBatchInsert(b *testing.B, db *sql.DB, ph string, startID, count int) {
	b.Helper()
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	q := fmt.Sprintf(`INSERT INTO users (id, name, age) VALUES (%s, %s, %s)`, ph, ph, ph)
	stmt, err := tx.Prepare(q)
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

func BenchmarkSBS_PointRead(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`SELECT name, age FROM users WHERE id = %s`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_Count(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`SELECT count(*) FROM users WHERE age >= %s`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_FilteredScan(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`SELECT id, name, age FROM users WHERE age = %s ORDER BY id LIMIT 20`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_Join(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE orders.id = %s`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_SingleInsert(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`INSERT INTO users (id, name, age) VALUES (%s, %s, %s)`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}(), func() string {
				if p.placeholder == "$" {
					return "$2"
				}
				return "?"
			}(), func() string {
				if p.placeholder == "$" {
					return "$3"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_BatchInsert(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			start := int(time.Now().UnixNano() % 1_000_000_000)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sbsBatchInsert(b, db, p.placeholder, start+(i*1000), 1000)
			}
		})
	}
}

func BenchmarkSBS_Update(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`UPDATE users SET age = %s WHERE id = %s`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}(), func() string {
				if p.placeholder == "$" {
					return "$2"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_Delete(b *testing.B) {
	for _, p := range sbsProviders(b) {
		b.Run(p.name, func(b *testing.B) {
			dir := b.TempDir()
			db, cleanup := p.open(b, dir)
			defer cleanup()
			sbsSeed(b, db, p.placeholder, 5000, 1000)

			q := fmt.Sprintf(`DELETE FROM users WHERE id = %s`, func() string {
				if p.placeholder == "$" {
					return "$1"
				}
				return "?"
			}())
			stmt, err := db.Prepare(q)
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
	}
}

func BenchmarkSBS_KV_PointRead(b *testing.B) {
	type kvEngine struct {
		name string
		fn   func(b *testing.B, dir string) (put func(id int), get func(id int) error, cleanup func())
	}
	engines := []kvEngine{
		{
			name: "Velocity_Native",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "velocity_native")
				db, err := velocity.NewWithConfig(velocity.Config{
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
				})
				if err != nil {
					b.Fatal(err)
				}
				put := func(id int) {
					key := []byte(fmt.Sprintf("users:%d", id))
					data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
					db.Put(key, data)
				}
				get := func(id int) error {
					key := []byte(fmt.Sprintf("users:%d", id))
					_, err := db.Get(key)
					return err
				}
				return put, get, func() {
					db.Close()
					os.RemoveAll(path)
				}
			},
		},
		{
			name: "Velocity_SQL_Cached",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "vsql_kv_cached")
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
					},
				}
				db, err := sql.Open(sqldriver.DriverName, path)
				if err != nil {
					b.Fatal(err)
				}
				for _, stmt := range []string{
					`DROP TABLE IF EXISTS users`,
					`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`,
				} {
					db.Exec(stmt)
				}
				db.Exec(`CREATE INDEX idx_users_age ON users (age)`)
				putStmt, _ := db.Prepare(`INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
				getStmt, _ := db.Prepare(`SELECT name, age FROM users WHERE id = ?`)
				put := func(id int) {
					putStmt.Exec(id, fmt.Sprintf("user_%d", id), 20+(id%50))
				}
				get := func(id int) error {
					var name string
					var age int
					return getStmt.QueryRow(id).Scan(&name, &age)
				}
				return put, get, func() {
					putStmt.Close()
					getStmt.Close()
					db.Close()
					delete(sqldriver.DSNConfigs, path)
					os.RemoveAll(path)
				}
			},
		},
		{
			name: "SQLite",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "sqlite_kv.db")
				db, err := sql.Open("sqlite3", path)
				if err != nil {
					b.Fatal(err)
				}
				for _, pragma := range []string{
					`PRAGMA journal_mode = WAL`,
					`PRAGMA synchronous = NORMAL`,
					`PRAGMA temp_store = MEMORY`,
				} {
					db.Exec(pragma)
				}
				for _, stmt := range []string{
					`DROP TABLE IF EXISTS users`,
					`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`,
				} {
					db.Exec(stmt)
				}
				db.Exec(`CREATE INDEX idx_users_age ON users (age)`)
				putStmt, _ := db.Prepare(`INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
				getStmt, _ := db.Prepare(`SELECT name, age FROM users WHERE id = ?`)
				put := func(id int) {
					putStmt.Exec(id, fmt.Sprintf("user_%d", id), 20+(id%50))
				}
				get := func(id int) error {
					var name string
					var age int
					return getStmt.QueryRow(id).Scan(&name, &age)
				}
				return put, get, func() {
					putStmt.Close()
					getStmt.Close()
					db.Close()
					os.RemoveAll(path)
				}
			},
		},
	}

	for _, eng := range engines {
		b.Run(eng.name, func(b *testing.B) {
			dir := b.TempDir()
			put, get, cleanup := eng.fn(b, dir)
			defer cleanup()
			ctx := context.Background()
			_ = ctx

			b.Run("Write", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					put(i + 1)
				}
			})

			seedCount := 100000
			for i := 0; i < seedCount; i++ {
				put(i + 1)
			}

			b.Run("Read", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					id := (i % seedCount) + 1
					if err := get(id); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkSBS_KV_SearchCount(b *testing.B) {
	type kvSearchEngine struct {
		name string
		fn   func(b *testing.B, dir string) (setup func(count int), search func(minAge int) error, cleanup func())
	}
	engines := []kvSearchEngine{
		{
			name: "Velocity_Native",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "velocity_native_search")
				db, err := velocity.NewWithConfig(velocity.Config{
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
				})
				if err != nil {
					b.Fatal(err)
				}
				setup := func(count int) {
					for i := 0; i < count; i++ {
						id := i + 1
						key := []byte(fmt.Sprintf("users:%d", id))
						data, _ := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), 20+(id%50))
						db.Put(key, data)
					}
				}
				search := func(minAge int) error {
					_, err := db.SearchCount(velocity.SearchQuery{
						Prefix: "users",
						Filters: []velocity.SearchFilter{
							{Field: "age", Op: ">=", Value: minAge},
						},
					})
					return err
				}
				return setup, search, func() {
					db.Close()
					os.RemoveAll(path)
				}
			},
		},
		{
			name: "Velocity_SQL_Cached",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "vsql_search_cached")
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
					},
				}
				db, err := sql.Open(sqldriver.DriverName, path)
				if err != nil {
					b.Fatal(err)
				}
				for _, stmt := range []string{
					`DROP TABLE IF EXISTS users`,
					`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`,
				} {
					db.Exec(stmt)
				}
				db.Exec(`CREATE INDEX idx_users_age ON users (age)`)
				setup := func(count int) {
					tx, _ := db.Begin()
					stmt, _ := tx.Prepare(`INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
					for i := 0; i < count; i++ {
						id := i + 1
						stmt.Exec(id, fmt.Sprintf("user_%d", id), 20+(id%50))
					}
					stmt.Close()
					tx.Commit()
				}
				stmt, _ := db.Prepare(`SELECT count(*) FROM users WHERE age >= ?`)
				search := func(minAge int) error {
					var count int
					return stmt.QueryRow(minAge).Scan(&count)
				}
				return setup, search, func() {
					stmt.Close()
					db.Close()
					delete(sqldriver.DSNConfigs, path)
					os.RemoveAll(path)
				}
			},
		},
		{
			name: "SQLite",
			fn: func(b *testing.B, dir string) (func(int), func(int) error, func()) {
				path := filepath.Join(dir, "sqlite_search.db")
				db, err := sql.Open("sqlite3", path)
				if err != nil {
					b.Fatal(err)
				}
				for _, pragma := range []string{
					`PRAGMA journal_mode = WAL`,
					`PRAGMA synchronous = NORMAL`,
					`PRAGMA temp_store = MEMORY`,
				} {
					db.Exec(pragma)
				}
				for _, stmt := range []string{
					`DROP TABLE IF EXISTS users`,
					`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`,
				} {
					db.Exec(stmt)
				}
				db.Exec(`CREATE INDEX idx_users_age ON users (age)`)
				setup := func(count int) {
					tx, _ := db.Begin()
					stmt, _ := tx.Prepare(`INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
					for i := 0; i < count; i++ {
						id := i + 1
						stmt.Exec(id, fmt.Sprintf("user_%d", id), 20+(id%50))
					}
					stmt.Close()
					tx.Commit()
				}
				stmt, _ := db.Prepare(`SELECT count(*) FROM users WHERE age >= ?`)
				search := func(minAge int) error {
					var count int
					return stmt.QueryRow(minAge).Scan(&count)
				}
				return setup, search, func() {
					stmt.Close()
					db.Close()
					os.RemoveAll(path)
				}
			},
		},
	}

	for _, eng := range engines {
		b.Run(eng.name, func(b *testing.B) {
			dir := b.TempDir()
			setup, search, cleanup := eng.fn(b, dir)
			defer cleanup()
			setup(50000)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := search(30); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

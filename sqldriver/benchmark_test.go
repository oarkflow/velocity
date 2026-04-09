package sqldriver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity"
)

func BenchmarkVelocityNativeVsSQL(b *testing.B) {
	b.Run("Insert/Native", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "native_insert")
		db := openNativeBenchDB(b, path)
		defer db.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, err := json.Marshal(map[string]interface{}{
				"id":   i + 1,
				"name": fmt.Sprintf("native_user_%d", i+1),
				"age":  20 + ((i + 1) % 50),
			})
			if err != nil {
				b.Fatal(err)
			}
			if err := db.Put([]byte(fmt.Sprintf("users:%d", i+1)), payload); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Insert/SQL", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "sql_insert")
		db := openSQLBenchDB(b, path)
		defer db.Close()

		ctx := context.Background()
		if _, err := db.ExecContext(ctx, `CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`); err != nil {
			b.Fatal(err)
		}
		stmt, err := db.PrepareContext(ctx, `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
		if err != nil {
			b.Fatal(err)
		}
		defer stmt.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := stmt.ExecContext(ctx, i+1, fmt.Sprintf("sql_user_%d", i+1), 20+((i+1)%50)); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Read/Native", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "native_read")
		db := openNativeBenchDB(b, path)
		defer db.Close()
		seedNativeBenchUsers(b, db, 5000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Get([]byte(fmt.Sprintf("users:%d", (i%5000)+1))); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Read/SQL", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "sql_read")
		db := openSQLBenchDB(b, path)
		defer db.Close()
		seedSQLBenchUsers(b, db, 5000)

		ctx := context.Background()
		stmt, err := db.PrepareContext(ctx, `SELECT name, age FROM users WHERE id = ?`)
		if err != nil {
			b.Fatal(err)
		}
		defer stmt.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var name string
			var age int
			if err := stmt.QueryRowContext(ctx, (i%5000)+1).Scan(&name, &age); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SearchCount/Native", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "native_search")
		db := openNativeBenchDB(b, path)
		defer db.Close()
		seedNativeBenchUsers(b, db, 5000)

		query := velocity.SearchQuery{
			Prefix: "users",
			Filters: []velocity.SearchFilter{
				{Field: "age", Op: ">=", Value: 40},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.SearchCount(query); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SearchCount/SQL", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "sql_search")
		db := openSQLBenchDB(b, path)
		defer db.Close()
		seedSQLBenchUsers(b, db, 5000)

		ctx := context.Background()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var count int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE age >= ?`, 40).Scan(&count); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchSchema() map[string]*velocity.SearchSchema {
	return map[string]*velocity.SearchSchema{
		"users": {
			Fields: []velocity.SearchSchemaField{
				{Name: "id", Searchable: true, HashSearch: true},
				{Name: "name", Searchable: true},
				{Name: "age", Searchable: true, HashSearch: true},
			},
		},
	}
}

func benchConfig(path string) velocity.Config {
	return velocity.Config{
		Path:              path,
		SearchSchemas:     benchSchema(),
		DisableEncryption: true,
		DisableWAL:        true,
		DisableFsync:      true,
		PerformanceMode:   "performance",
	}
}

func openNativeBenchDB(b *testing.B, path string) *velocity.DB {
	b.Helper()
	db, err := velocity.NewWithConfig(benchConfig(path))
	if err != nil {
		b.Fatal(err)
	}
	return db
}

func openSQLBenchDB(b *testing.B, path string) *sql.DB {
	b.Helper()
	_ = os.RemoveAll(path)
	DSNConfigs[path] = benchConfig(path)
	b.Cleanup(func() {
		delete(DSNConfigs, path)
	})

	db, err := sql.Open(DriverName, path)
	if err != nil {
		b.Fatal(err)
	}
	return db
}

func seedNativeBenchUsers(b *testing.B, db *velocity.DB, count int) {
	b.Helper()
	batch := db.NewBatchWriter(count)
	for i := 1; i <= count; i++ {
		payload, err := json.Marshal(map[string]interface{}{
			"id":   i,
			"name": fmt.Sprintf("native_user_%d", i),
			"age":  20 + (i % 50),
		})
		if err != nil {
			b.Fatal(err)
		}
		if err := batch.Put([]byte(fmt.Sprintf("users:%d", i)), payload); err != nil {
			b.Fatal(err)
		}
	}
	if err := batch.Flush(); err != nil {
		b.Fatal(err)
	}
}

func seedSQLBenchUsers(b *testing.B, db *sql.DB, count int) {
	b.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT, age BIGINT)`); err != nil {
		b.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO users (id, name, age) VALUES (?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		b.Fatal(err)
	}
	defer stmt.Close()
	for i := 1; i <= count; i++ {
		if _, err := stmt.ExecContext(ctx, i, fmt.Sprintf("sql_user_%d", i), 20+(i%50)); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

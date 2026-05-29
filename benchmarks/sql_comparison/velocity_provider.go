package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

type VelocityProvider struct {
	db                *velocity.DB
	sqlDB             *sql.DB
	sqlConn           *sql.Conn
	useSQL            bool
	encrypted         bool
	reopenedForSearch bool
	path              string
}

func NewVelocityProvider(path string, useSQL bool) *VelocityProvider {
	return &VelocityProvider{
		path:   path,
		useSQL: useSQL,
	}
}

func NewVelocityEncryptedProvider(path string) *VelocityProvider {
	return &VelocityProvider{
		path:      path,
		encrypted: true,
	}
}

func (p *VelocityProvider) Name() string {
	if p.encrypted {
		return "Velocity (Encrypted)"
	}
	if p.useSQL {
		return "Velocity (SQL)"
	}
	return "Velocity (Native)"
}

func (p *VelocityProvider) searchSchema() map[string]*velocity.SearchSchema {
	if p.useSQL {
		return map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "age", ValueIndex: true},
				},
			},
		}
	}
	return map[string]*velocity.SearchSchema{
		"users": {
			Fields: []velocity.SearchSchemaField{
				{Name: "email", HashSearch: true},
				{Name: "age", ValueIndex: true},
			},
		},
	}
}

func (p *VelocityProvider) config() velocity.Config {
	if p.encrypted {
		return velocity.Config{
			Path:            p.path,
			PerformanceMode: "performance",
			MasterKey:       benchmarkEncryptionKey,
			SearchSchemas:   p.searchSchema(),
		}
	}
	return velocity.Config{
		Path:                    p.path,
		PerformanceMode:         "performance",
		SearchSchemas:           p.searchSchema(),
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		DisableIndexPersistence: p.useSQL,
	}
}

func (p *VelocityProvider) Setup(ctx context.Context) error {
	os.RemoveAll(p.path)
	p.reopenedForSearch = false

	if p.useSQL {
		// Use the DSN configuration for the SQL driver
		sqldriver.DSNConfigs[p.path] = velocity.Config{
			Path:                    p.path,
			PerformanceMode:         "performance",
			SearchSchemas:           p.searchSchema(),
			DisableEncryption:       true,
			DisableWAL:              true,
			DisableFsync:            true,
			DisableIndexPersistence: true,
		}

		db, err := sql.Open("velocity", p.path)
		if err != nil {
			return err
		}
		p.sqlDB = db
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		p.sqlConn = conn
	} else {
		db, err := velocity.NewWithConfig(p.config())
		if err != nil {
			return err
		}
		p.db = db
	}
	return nil
}

func (p *VelocityProvider) Cleanup(ctx context.Context) error {
	if p.sqlConn != nil {
		p.sqlConn.Close()
		p.sqlConn = nil
	}
	if p.sqlDB != nil {
		p.sqlDB.Close()
	}
	if p.db != nil {
		p.db.Close()
	}
	return os.RemoveAll(p.path)
}

func (p *VelocityProvider) Insert(ctx context.Context, id int, name string, age int) error {
	if p.useSQL {
		if p.sqlConn != nil {
			return p.sqlConn.Raw(func(driverConn any) error {
				if inserter, ok := driverConn.(interface {
					InsertRowFunc(table string, columns []string, fill func(dst []any)) error
				}); ok {
					return inserter.InsertRowFunc("users", []string{"id", "name", "age"}, func(dst []any) {
						dst[0] = id
						dst[1] = name
						dst[2] = age
					})
				}
				_, err := p.sqlDB.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)", id, name, age)
				return err
			})
		}
		_, err := p.sqlDB.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)", id, name, age)
		return err
	}

	key := []byte(fmt.Sprintf("users:%d", id))
	data, err := benchmarkUserJSON(id, name, age)
	if err != nil {
		return err
	}
	return p.db.Put(key, data)
}

func (p *VelocityProvider) Read(ctx context.Context, id int) (string, int, error) {
	if p.useSQL {
		if p.sqlConn != nil {
			var outName string
			var outAge int
			err := p.sqlConn.Raw(func(driverConn any) error {
				if reader, ok := driverConn.(interface {
					ReadByID(table string, id any, columns []string) ([]any, error)
				}); ok {
					values, err := reader.ReadByID("users", id, []string{"name", "age"})
					if err != nil {
						return err
					}
					if len(values) >= 2 {
						if name, ok := values[0].(string); ok {
							outName = name
						}
						switch age := values[1].(type) {
						case int:
							outAge = age
						case int64:
							outAge = int(age)
						case float64:
							outAge = int(age)
						}
					}
					return nil
				}
				return p.sqlDB.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = ?", id).Scan(&outName, &outAge)
			})
			return outName, outAge, err
		}
		var name string
		var age int
		err := p.sqlDB.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = ?", id).Scan(&name, &age)
		return name, age, err
	}

	key := []byte(fmt.Sprintf("users:%d", id))
	val, err := p.db.Get(key)
	if err != nil {
		return "", 0, err
	}
	var data struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	if err := json.Unmarshal(val, &data); err != nil {
		return "", 0, err
	}
	return data.Name, data.Age, nil
}

func (p *VelocityProvider) Update(ctx context.Context, id int, age int) error {
	if p.useSQL {
		_, err := p.sqlDB.ExecContext(ctx, "UPDATE users SET age = ? WHERE id = ?", age, id)
		return err
	}

	key := []byte(fmt.Sprintf("users:%d", id))
	// In native we just overwrite
	data, err := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), age)
	if err != nil {
		return err
	}
	return p.db.Put(key, data)
}

func (p *VelocityProvider) Delete(ctx context.Context, id int) error {
	if p.useSQL {
		_, err := p.sqlDB.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
		return err
	}

	key := []byte(fmt.Sprintf("users:%d", id))
	return p.db.Delete(key)
}

func (p *VelocityProvider) Search(ctx context.Context, minAge int) (int, error) {
	if p.useSQL {
		rows, err := p.sqlDB.QueryContext(ctx, "SELECT count(*) FROM users WHERE age >= ?", minAge)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		var count int
		if rows.Next() {
			rows.Scan(&count)
		}
		return count, nil
	}

	if p.encrypted {
		return p.db.SearchCount(velocity.SearchQuery{
			Prefix: "users",
			Filters: []velocity.SearchFilter{
				{Field: "email", Op: "==", Value: benchmarkEmail(encryptedBenchmarkTargetID), HashOnly: true},
				{Field: "age", Op: ">=", Value: minAge},
			},
			Limit: 1,
		})
	}

	results, err := p.db.Search(velocity.SearchQuery{
		Prefix: "users",
		Filters: []velocity.SearchFilter{
			{Field: "email", Op: "==", Value: benchmarkEmail(encryptedBenchmarkTargetID), HashOnly: true},
			{Field: "age", Op: ">=", Value: minAge},
		},
		Limit: 1,
	})
	return len(results), err
}

func (p *VelocityProvider) PrepareSearchBenchmark(ctx context.Context, minAge int) error {
	if !p.encrypted {
		return nil
	}
	if !p.reopenedForSearch {
		if err := p.db.Close(); err != nil {
			return err
		}
		db, err := velocity.NewWithConfig(p.config())
		if err != nil {
			return err
		}
		p.db = db
		p.reopenedForSearch = true
	}
	_, err := p.db.SearchCount(velocity.SearchQuery{
		Prefix: "users",
		Filters: []velocity.SearchFilter{
			{Field: "email", Op: "==", Value: benchmarkEmail(encryptedBenchmarkTargetID), HashOnly: true},
			{Field: "age", Op: ">=", Value: minAge},
		},
		Limit: 1,
	})
	return err
}

func (p *VelocityProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	if p.useSQL {
		if p.sqlConn == nil {
			return fmt.Errorf("velocity SQL connection is not initialized")
		}
		return p.sqlConn.Raw(func(driverConn any) error {
			if bulk, ok := driverConn.(interface {
				BulkInsertFunc(table string, columns []string, count int, fill func(i int, dst []any)) (int64, error)
			}); ok {
				_, err := bulk.BulkInsertFunc("users", []string{"id", "name", "age"}, count, func(i int, dst []any) {
					id := startID + i
					dst[0] = id
					dst[1] = fmt.Sprintf("user_%d", id)
					dst[2] = 20 + (id % 50)
				})
				return err
			}
			rows := make([][]any, count)
			for i := 0; i < count; i++ {
				id := startID + i
				rows[i] = []any{id, fmt.Sprintf("user_%d", id), 20 + (id % 50)}
			}
			tx, err := p.sqlDB.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			stmt, err := tx.PrepareContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)")
			if err != nil {
				tx.Rollback()
				return err
			}
			defer stmt.Close()
			for _, row := range rows {
				if _, err := stmt.ExecContext(ctx, row...); err != nil {
					tx.Rollback()
					return err
				}
			}
			return tx.Commit()
		})
	}

	batch := p.db.NewBatchWriter(count)
	for i := 0; i < count; i++ {
		id := startID + i
		name := fmt.Sprintf("user_%d", id)
		key := []byte(fmt.Sprintf("users:%d", id))
		data, err := benchmarkUserJSON(id, name, 20+(id%50))
		if err != nil {
			return err
		}
		if err := batch.Put(key, data); err != nil {
			return err
		}
	}
	return batch.Flush()
}

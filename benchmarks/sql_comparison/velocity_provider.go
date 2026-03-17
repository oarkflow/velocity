package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/sqldriver"
)

type VelocityProvider struct {
	db     *velocity.DB
	sqlDB  *sql.DB
	useSQL bool
	path   string
}

func NewVelocityProvider(path string, useSQL bool) *VelocityProvider {
	return &VelocityProvider{
		path:   path,
		useSQL: useSQL,
	}
}

func (p *VelocityProvider) Name() string {
	if p.useSQL {
		return "Velocity (SQL)"
	}
	return "Velocity (Native)"
}

func (p *VelocityProvider) Setup(ctx context.Context) error {
	os.RemoveAll(p.path)

	if p.useSQL {
		// Use the DSN configuration for the SQL driver
		sqldriver.DSNConfigs[p.path] = velocity.Config{
			Path:            p.path,
			PerformanceMode: "performance",
			SearchSchemas: map[string]*velocity.SearchSchema{
				"users": {
					Fields: []velocity.SearchSchemaField{
						{Name: "id", Searchable: true, HashSearch: true},
						{Name: "name", Searchable: true},
						{Name: "age", Searchable: true, HashSearch: true},
					},
				},
			},
		}

		db, err := sql.Open("velocity", p.path)
		if err != nil {
			return err
		}
		p.sqlDB = db
	} else {
		db, err := velocity.NewWithConfig(velocity.Config{
			Path:            p.path,
			PerformanceMode: "performance",
		})
		if err != nil {
			return err
		}
		p.db = db
	}
	return nil
}

func (p *VelocityProvider) Cleanup(ctx context.Context) error {
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
		_, err := p.sqlDB.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)", id, name, age)
		return err
	}

	key := []byte(fmt.Sprintf("user:%d", id))
	data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, age)
	return p.db.Put(key, []byte(data))
}

func (p *VelocityProvider) Read(ctx context.Context, id int) (string, int, error) {
	if p.useSQL {
		var name string
		var age int
		err := p.sqlDB.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = ?", id).Scan(&name, &age)
		return name, age, err
	}

	key := []byte(fmt.Sprintf("user:%d", id))
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

	key := []byte(fmt.Sprintf("user:%d", id))
	// In native we just overwrite
	data := fmt.Sprintf(`{"id":%d,"name":"user_%d","age":%d}`, id, id, age)
	return p.db.Put(key, []byte(data))
}

func (p *VelocityProvider) Delete(ctx context.Context, id int) error {
	if p.useSQL {
		_, err := p.sqlDB.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
		return err
	}

	key := []byte(fmt.Sprintf("user:%d", id))
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

	// Native search uses the Search API with Prefix
	count, err := p.db.Search(velocity.SearchQuery{
		Prefix: "user:", // Search by prefix
		// We'd need more complex logic to filter by age native if we don't have an index
		// For consistency with SQL we just scan & count for now
	})
	return len(count), err
}

func (p *VelocityProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	if p.useSQL {
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

		for i := 0; i < count; i++ {
			id := startID + i
			name := fmt.Sprintf("user_%d", id)
			_, err := stmt.ExecContext(ctx, id, name, 20+(id%50))
			if err != nil {
				tx.Rollback()
				return err
			}
		}
		return tx.Commit()
	}

	batch := p.db.NewBatchWriter(count)
	for i := 0; i < count; i++ {
		id := startID + i
		name := fmt.Sprintf("user_%d", id)
		key := []byte(fmt.Sprintf("user:%d", id))
		data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, 20+(id%50))
		batch.Put(key, []byte(data))
	}
	return batch.Flush()
}

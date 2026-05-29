package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteProvider struct {
	db   *sql.DB
	path string
}

func NewSQLiteProvider(path string) *SQLiteProvider {
	return &SQLiteProvider{path: path}
}

func (p *SQLiteProvider) Name() string {
	return "SQLite"
}

func (p *SQLiteProvider) Setup(ctx context.Context) error {
	if err := os.Remove(p.path); err != nil && !os.IsNotExist(err) {
		return err
	}

	db, err := sql.Open("sqlite3", p.path)
	if err != nil {
		return err
	}
	p.db = db

	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA busy_timeout = 5000",
	}
	for _, pragma := range pragmas {
		if _, err := p.db.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}

	_, err = p.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		name TEXT,
		age INTEGER
	)`)
	if err != nil {
		return err
	}

	_, err = p.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_users_age ON users (age)")
	if err != nil {
		return err
	}

	_, err = p.db.ExecContext(ctx, "DELETE FROM users")
	return err
}

func (p *SQLiteProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			return err
		}
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(p.path + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (p *SQLiteProvider) Insert(ctx context.Context, id int, name string, age int) error {
	_, err := p.db.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)", id, name, age)
	return err
}

func (p *SQLiteProvider) Read(ctx context.Context, id int) (string, int, error) {
	var name string
	var age int
	err := p.db.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = ?", id).Scan(&name, &age)
	return name, age, err
}

func (p *SQLiteProvider) Update(ctx context.Context, id int, age int) error {
	_, err := p.db.ExecContext(ctx, "UPDATE users SET age = ? WHERE id = ?", age, id)
	return err
}

func (p *SQLiteProvider) Delete(ctx context.Context, id int) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	return err
}

func (p *SQLiteProvider) Search(ctx context.Context, minAge int) (int, error) {
	var count int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE age >= ?", minAge).Scan(&count)
	return count, err
}

func (p *SQLiteProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	tx, err := p.db.BeginTx(ctx, nil)
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
		if _, err := stmt.ExecContext(ctx, id, name, 20+(id%50)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

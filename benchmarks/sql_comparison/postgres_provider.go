package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

type PostgresProvider struct {
	db  *sql.DB
	dsn string
}

func NewPostgresProvider() *PostgresProvider {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		// Default local dev DSN - use 'postgres' database which usually exists
		dsn = "postgres://postgres:postgres@localhost:5432/velocity_bench?sslmode=disable"
	}
	return &PostgresProvider{dsn: dsn}
}

func (p *PostgresProvider) Name() string {
	return "PostgreSQL"
}

func (p *PostgresProvider) Setup(ctx context.Context) error {
	db, err := sql.Open("postgres", p.dsn)
	if err != nil {
		return err
	}
	p.db = db

	// Create table
	_, err = p.db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INT PRIMARY KEY,
		name VARCHAR(255),
		age INT
	)`)
	if err != nil {
		return err
	}

	_, err = p.db.Exec("CREATE INDEX IF NOT EXISTS idx_age ON users (age)")
	if err != nil {
		return err
	}

	// Truncate
	_, err = p.db.Exec("TRUNCATE TABLE users")
	return err
}

func (p *PostgresProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		_, _ = p.db.Exec("DROP TABLE IF EXISTS users")
		return p.db.Close()
	}
	return nil
}

func (p *PostgresProvider) Insert(ctx context.Context, id int, name string, age int) error {
	_, err := p.db.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES ($1, $2, $3)", id, name, age)
	return err
}

func (p *PostgresProvider) Read(ctx context.Context, id int) (string, int, error) {
	var name string
	var age int
	err := p.db.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = $1", id).Scan(&name, &age)
	return name, age, err
}

func (p *PostgresProvider) Update(ctx context.Context, id int, age int) error {
	_, err := p.db.ExecContext(ctx, "UPDATE users SET age = $1 WHERE id = $2", age, id)
	return err
}

func (p *PostgresProvider) Delete(ctx context.Context, id int) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}

func (p *PostgresProvider) Search(ctx context.Context, minAge int) (int, error) {
	var count int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE age >= $1", minAge).Scan(&count)
	return count, err
}

func (p *PostgresProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO users (id, name, age) VALUES ($1, $2, $3)")
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

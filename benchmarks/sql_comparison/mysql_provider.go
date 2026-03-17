package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLProvider struct {
	db  *sql.DB
	dsn string
}

func NewMySQLProvider() *MySQLProvider {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		// Default local dev DSN - use 'mysql' database which usually exists
		dsn = "root:T#sT1234@tcp(localhost:3306)/mysql"
	}
	return &MySQLProvider{dsn: dsn}
}

func (p *MySQLProvider) Name() string {
	return "MySQL"
}

func (p *MySQLProvider) Setup(ctx context.Context) error {
	db, err := sql.Open("mysql", p.dsn)
	if err != nil {
		return err
	}
	p.db = db

	// Create table
	_, err = p.db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INT PRIMARY KEY,
		name VARCHAR(255),
		age INT,
		INDEX idx_age (age)
	) ENGINE=InnoDB`)
	if err != nil {
		return err
	}

	// Truncate
	_, err = p.db.Exec("TRUNCATE TABLE users")
	return err
}

func (p *MySQLProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		_, _ = p.db.Exec("DROP TABLE IF EXISTS users")
		return p.db.Close()
	}
	return nil
}

func (p *MySQLProvider) Insert(ctx context.Context, id int, name string, age int) error {
	_, err := p.db.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES (?, ?, ?)", id, name, age)
	return err
}

func (p *MySQLProvider) Read(ctx context.Context, id int) (string, int, error) {
	var name string
	var age int
	err := p.db.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = ?", id).Scan(&name, &age)
	return name, age, err
}

func (p *MySQLProvider) Update(ctx context.Context, id int, age int) error {
	_, err := p.db.ExecContext(ctx, "UPDATE users SET age = ? WHERE id = ?", age, id)
	return err
}

func (p *MySQLProvider) Delete(ctx context.Context, id int) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	return err
}

func (p *MySQLProvider) Search(ctx context.Context, minAge int) (int, error) {
	var count int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE age >= ?", minAge).Scan(&count)
	return count, err
}

func (p *MySQLProvider) BatchInsert(ctx context.Context, startID int, count int) error {
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
		_, err := stmt.ExecContext(ctx, id, name, 20+(id%50))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

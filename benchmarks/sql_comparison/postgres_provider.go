package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

type PostgresProvider struct {
	db        *sql.DB
	dsn       string
	encrypted bool
}

func NewPostgresProvider() *PostgresProvider {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		// Default local dev DSN - use 'postgres' database which usually exists
		dsn = "postgres://postgres:postgres@localhost:5432/velocity_bench?sslmode=disable"
	}
	return &PostgresProvider{dsn: dsn}
}

func NewPostgresEncryptedProvider() *PostgresProvider {
	p := NewPostgresProvider()
	p.encrypted = true
	return p
}

func (p *PostgresProvider) Name() string {
	if p.encrypted {
		return "PostgreSQL (Encrypted+Derived)"
	}
	return "PostgreSQL"
}

func (p *PostgresProvider) tableName() string {
	if p.encrypted {
		return "users_secure"
	}
	return "users"
}

func (p *PostgresProvider) Setup(ctx context.Context) error {
	db, err := sql.Open("postgres", p.dsn)
	if err != nil {
		return err
	}
	p.db = db

	if p.encrypted {
		_, err = p.db.Exec(`CREATE TABLE IF NOT EXISTS users_secure (
			id INT PRIMARY KEY,
			payload BYTEA NOT NULL,
			email_hash CHAR(64) NOT NULL,
			age INT NOT NULL
		)`)
		if err != nil {
			return err
		}
		_, err = p.db.Exec("CREATE INDEX IF NOT EXISTS idx_users_secure_email_hash ON users_secure (email_hash)")
		if err != nil {
			return err
		}
		_, err = p.db.Exec("CREATE INDEX IF NOT EXISTS idx_users_secure_age ON users_secure (age)")
		if err != nil {
			return err
		}
		_, err = p.db.Exec("CREATE INDEX IF NOT EXISTS idx_users_secure_email_age ON users_secure (email_hash, age)")
		if err != nil {
			return err
		}
		_, err = p.db.Exec("TRUNCATE TABLE users_secure")
		return err
	}

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

	_, err = p.db.Exec("TRUNCATE TABLE users")
	return err
}

func (p *PostgresProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		_, _ = p.db.Exec("DROP TABLE IF EXISTS users")
		_, _ = p.db.Exec("DROP TABLE IF EXISTS users_secure")
		return p.db.Close()
	}
	return nil
}

func (p *PostgresProvider) Insert(ctx context.Context, id int, name string, age int) error {
	if p.encrypted {
		payload, err := benchmarkUserJSON(id, name, age)
		if err != nil {
			return err
		}
		encrypted, err := encryptBenchmarkPayload(benchmarkEncryptionKey, payload)
		if err != nil {
			return err
		}
		_, err = p.db.ExecContext(ctx, "INSERT INTO users_secure (id, payload, email_hash, age) VALUES ($1, $2, $3, $4)", id, encrypted, benchmarkDerivedHash(benchmarkEmail(id)), age)
		return err
	}
	_, err := p.db.ExecContext(ctx, "INSERT INTO users (id, name, age) VALUES ($1, $2, $3)", id, name, age)
	return err
}

func (p *PostgresProvider) Read(ctx context.Context, id int) (string, int, error) {
	if p.encrypted {
		var payload []byte
		err := p.db.QueryRowContext(ctx, "SELECT payload FROM users_secure WHERE id = $1", id).Scan(&payload)
		if err != nil {
			return "", 0, err
		}
		plaintext, err := decryptBenchmarkPayload(benchmarkEncryptionKey, payload)
		if err != nil {
			return "", 0, err
		}
		var user benchmarkUser
		if err := json.Unmarshal(plaintext, &user); err != nil {
			return "", 0, err
		}
		return user.Name, user.Age, nil
	}
	var name string
	var age int
	err := p.db.QueryRowContext(ctx, "SELECT name, age FROM users WHERE id = $1", id).Scan(&name, &age)
	return name, age, err
}

func (p *PostgresProvider) Update(ctx context.Context, id int, age int) error {
	if p.encrypted {
		payload, err := benchmarkUserJSON(id, fmt.Sprintf("user_%d", id), age)
		if err != nil {
			return err
		}
		encrypted, err := encryptBenchmarkPayload(benchmarkEncryptionKey, payload)
		if err != nil {
			return err
		}
		_, err = p.db.ExecContext(ctx, "UPDATE users_secure SET payload = $1, email_hash = $2, age = $3 WHERE id = $4", encrypted, benchmarkDerivedHash(benchmarkEmail(id)), age, id)
		return err
	}
	_, err := p.db.ExecContext(ctx, "UPDATE users SET age = $1 WHERE id = $2", age, id)
	return err
}

func (p *PostgresProvider) Delete(ctx context.Context, id int) error {
	if p.encrypted {
		_, err := p.db.ExecContext(ctx, "DELETE FROM users_secure WHERE id = $1", id)
		return err
	}
	_, err := p.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}

func (p *PostgresProvider) Search(ctx context.Context, minAge int) (int, error) {
	if p.encrypted {
		var count int
		err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users_secure WHERE email_hash = $1 AND age >= $2", benchmarkDerivedHash(benchmarkEmail(encryptedBenchmarkTargetID)), minAge).Scan(&count)
		return count, err
	}
	var count int
	err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE age >= $1", minAge).Scan(&count)
	return count, err
}

func (p *PostgresProvider) PrepareSearchBenchmark(ctx context.Context, minAge int) error {
	_, err := p.Search(ctx, minAge)
	return err
}

func (p *PostgresProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	if p.encrypted {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, "INSERT INTO users_secure (id, payload, email_hash, age) VALUES ($1, $2, $3, $4)")
		if err != nil {
			tx.Rollback()
			return err
		}
		defer stmt.Close()

		for i := 0; i < count; i++ {
			id := startID + i
			name := fmt.Sprintf("user_%d", id)
			age := 20 + (id % 50)
			payload, err := benchmarkUserJSON(id, name, age)
			if err != nil {
				tx.Rollback()
				return err
			}
			encrypted, err := encryptBenchmarkPayload(benchmarkEncryptionKey, payload)
			if err != nil {
				tx.Rollback()
				return err
			}
			_, err = stmt.ExecContext(ctx, id, encrypted, benchmarkDerivedHash(benchmarkEmail(id)), age)
			if err != nil {
				tx.Rollback()
				return err
			}
		}
		return tx.Commit()
	}
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

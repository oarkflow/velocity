package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity/pkg/sqldriver"
)

func main() {
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	dsn := filepath.Join(dir, "velocity-data") + "?query_cache=true&query_cache_ttl=30s&query_cache_max_rows=500"

	db, err := sql.Open(sqldriver.DriverName, dsn)
	check(err)
	defer db.Close()

	mustExec(db, `CREATE TABLE users (
		uuid string PRIMARY KEY DEFAULT uuid(),
		id int INDEX,
		name string NOT NULL,
		bio string FULLTEXT,
		region string INDEX,
		price money DEFAULT 'USD 0.00',
		payload json,
		created_at timestampz DEFAULT now(),
		spend decimal VALUEINDEX
	)`)
	mustExec(db, `CREATE TABLE orders (
		uuid string PRIMARY KEY DEFAULT uuid(),
		user_id int INDEX,
		total money DEFAULT 'USD 0.00'
	)`)
	mustExec(db, `INSERT INTO users (id, name, bio, region, price, payload, spend) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		1, "Ada", "Analytical engine notes and symbolic computation", "EU", "USD 125.50", `{"tier":"founder","active":true}`, "125.50")

	tx, err := db.Begin()
	check(err)
	_, err = tx.Exec(`INSERT INTO users (id, name, bio, region, price, payload, spend) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		2, "Grace", "Compiler design and naval computing systems", "US", "USD 300.00", `{"tier":"staff","active":true}`, "300.00")
	check(err)
	_, err = tx.Exec(`INSERT INTO users (id, name, bio, region, payload, spend) VALUES (?, ?, ?, ?, ?, ?)`,
		3, "Barbara", "Compiler tooling and software engineering leadership", "US", `{"tier":"advisor","active":false}`, "210.25")
	check(err)
	_, err = tx.Exec(`INSERT INTO orders (user_id, total) VALUES (?, ?)`, 2, "USD 450.00")
	check(err)
	check(tx.Commit())

	mustExec(db, `UPDATE users SET spend = ? WHERE id = ?`, "150.75", 1)

	rows, err := db.Query(`SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id WHERE users.region = ?`, "US")
	check(err)
	defer rows.Close()
	for rows.Next() {
		var name string
		var total any
		check(rows.Scan(&name, &total))
		fmt.Printf("joined order: %s %#v\n", name, total)
	}
	check(rows.Err())

	var count int
	check(db.QueryRow(`SELECT COUNT(*) FROM users WHERE spend >= ?`, 100).Scan(&count))
	var uuid string
	var createdAt string
	var price any
	var payload any
	check(db.QueryRow(`SELECT uuid, created_at, price, payload FROM users WHERE id = ?`, 3).Scan(&uuid, &createdAt, &price, &payload))
	fulltextRows, err := db.Query(`SELECT id, name FROM users WHERE bio LIKE ?`, "%compiler%")
	check(err)
	defer fulltextRows.Close()
	for fulltextRows.Next() {
		var id int
		var name string
		check(fulltextRows.Scan(&id, &name))
		fmt.Printf("fulltext record: %d %s\n", id, name)
	}
	check(fulltextRows.Err())
	var equalityName string
	check(db.QueryRow(`SELECT name FROM users WHERE id = ?`, 2).Scan(&equalityName))
	fmt.Printf("users with spend >= 100: %d\n", count)
	fmt.Printf("id equality match: %s\n", equalityName)
	fmt.Printf("defaulted row: uuid=%s created_at=%s price=%#v payload=%#v\n", uuid, createdAt, price, payload)
}

func mustExec(db *sql.DB, query string, args ...any) {
	_, err := db.Exec(query, args...)
	check(err)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_sql_driver_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// Command sql_demo shows Velocity v2's SQL plugin end to end: table
// creation, CRUD, WHERE, ORDER BY/LIMIT, GROUP BY/aggregates, JOINs,
// non-correlated and correlated subqueries (EXISTS), transactions with a
// real rollback, and — separately — the same engine driven through the
// stdlib database/sql API instead of api.SQLEngine directly.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	sqlplugin "github.com/oarkflow/velocity/v2/plugins/sql"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-sql-demo-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
		{Name: "sql", Enabled: true},
	}}

	k := kernel.New(manifest)
	ctx := context.Background()
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), sqlplugin.NewPlugin("kv")}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	svc, ok := k.Registry().Lookup("sql")
	if !ok {
		log.Fatal("sql service not registered")
	}
	eng := svc.(api.SQLEngine)

	section("1. Schema + data")
	exec(ctx, eng, `CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(255), vip INT)`)
	exec(ctx, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount INT)`)
	exec(ctx, eng, `INSERT INTO customers (id, name, vip) VALUES (1, 'alice', 1)`)
	exec(ctx, eng, `INSERT INTO customers (id, name, vip) VALUES (2, 'bob', 0)`)
	exec(ctx, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (100, 1, 30)`)
	exec(ctx, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (101, 1, 40)`)
	exec(ctx, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (102, 2, 5)`)
	fmt.Println("created customers/orders and inserted 2 customers + 3 orders")

	section("2. WHERE + ORDER BY/LIMIT")
	rows := query(ctx, eng, `SELECT name FROM customers WHERE vip = 1`)
	fmt.Printf("vip customers: %v\n", rows)
	rows = query(ctx, eng, `SELECT amount FROM orders ORDER BY amount DESC LIMIT 2`)
	fmt.Printf("top 2 order amounts: %v\n", rows)

	section("3. GROUP BY + aggregate")
	rows = query(ctx, eng, `SELECT customer_id, COUNT(*), SUM(amount) FROM orders GROUP BY customer_id ORDER BY customer_id ASC`)
	for _, r := range rows {
		fmt.Printf("customer_id=%v orders=%v total=%v\n", r["customer_id"], r["COUNT(*)"], r["SUM(amount)"])
	}

	section("4. INNER JOIN")
	rows = query(ctx, eng, `SELECT customers.name, orders.amount FROM customers JOIN orders ON customers.id = orders.customer_id ORDER BY orders.amount ASC`)
	for _, r := range rows {
		fmt.Printf("%v ordered %v\n", r["name"], r["amount"])
	}

	section("5. Non-correlated subquery (IN)")
	rows = query(ctx, eng, `SELECT amount FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE vip = 1)`)
	fmt.Printf("orders from vip customers: %v\n", rows)

	section("6. Correlated subquery (EXISTS) — real per-row correlation, not a coincidence")
	rows = query(ctx, eng, `SELECT name FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id AND o.amount > 35)`)
	fmt.Printf("customers with an order over 35: %v (only alice has a >35 order)\n", rows)

	section("7. Transaction commit vs rollback")
	tx, err := eng.Begin(ctx)
	must(err)
	_, err = tx.Exec(ctx, `INSERT INTO customers (id, name, vip) VALUES (3, 'carol', 0)`)
	must(err)
	must(tx.Commit())
	rows = query(ctx, eng, `SELECT name FROM customers WHERE id = 3`)
	fmt.Printf("after commit, customer 3 exists: %v\n", rows)

	tx, err = eng.Begin(ctx)
	must(err)
	_, err = tx.Exec(ctx, `INSERT INTO customers (id, name, vip) VALUES (4, 'dave', 0)`)
	must(err)
	must(tx.Rollback())
	rows = query(ctx, eng, `SELECT name FROM customers WHERE id = 4`)
	fmt.Printf("after rollback, customer 4 rows (should be empty): %v\n", rows)

	section("8. UPDATE / DELETE")
	exec(ctx, eng, `UPDATE customers SET vip = 1 WHERE id = 2`)
	rows = query(ctx, eng, `SELECT name FROM customers WHERE vip = 1 ORDER BY name ASC`)
	fmt.Printf("vip customers after update: %v\n", rows)
	exec(ctx, eng, `DELETE FROM orders WHERE id = 102`)
	rows = query(ctx, eng, `SELECT id FROM orders ORDER BY id ASC`)
	fmt.Printf("remaining order ids after delete: %v\n", rows)

	section("9. Same engine via stdlib database/sql")
	db, err := sqlplugin.Open(eng.(*sqlplugin.Engine))
	must(err)
	defer db.Close()

	dbRows, err := db.QueryContext(ctx, `SELECT name FROM customers WHERE vip = ?`, 1)
	must(err)
	defer dbRows.Close()
	fmt.Println("vip customers via database/sql:")
	for dbRows.Next() {
		var name string
		must(dbRows.Scan(&name))
		fmt.Printf("  - %s\n", name)
	}
	must(dbRows.Err())

	_, err = db.ExecContext(ctx, `INSERT INTO customers (id, name, vip) VALUES (?, ?, ?)`, 5, "erin", 0)
	must(err)
	var count int
	must(db.QueryRowContext(ctx, `SELECT COUNT(*) FROM customers`).Scan(&count))
	fmt.Printf("total customers after database/sql insert: %d\n", count)

	fmt.Println("\ndone.")
}

func section(title string) { fmt.Printf("\n=== %s ===\n", title) }

func exec(ctx context.Context, eng api.SQLEngine, query string) {
	if _, err := eng.Exec(ctx, query); err != nil {
		log.Fatalf("exec %q: %v", query, err)
	}
}

func query(ctx context.Context, eng api.SQLEngine, q string) []api.Row {
	rows, err := eng.Query(ctx, q)
	if err != nil {
		log.Fatalf("query %q: %v", q, err)
	}
	return rows
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

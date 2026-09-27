package sql

import (
	"context"
	"testing"
)

func TestOrderByAndLimit(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE items (id INT PRIMARY KEY, name VARCHAR(255), price INT)`)
	mustExec(t, eng, `INSERT INTO items (id, name, price) VALUES (1, 'a', 30)`)
	mustExec(t, eng, `INSERT INTO items (id, name, price) VALUES (2, 'b', 10)`)
	mustExec(t, eng, `INSERT INTO items (id, name, price) VALUES (3, 'c', 20)`)

	rows, err := eng.Query(ctx, `SELECT name FROM items ORDER BY price ASC`)
	if err != nil {
		t.Fatalf("order by asc: %v", err)
	}
	want := []string{"b", "c", "a"}
	for i, w := range want {
		if rows[i]["name"] != w {
			t.Fatalf("row %d: expected %q, got %v (full: %v)", i, w, rows[i]["name"], rows)
		}
	}

	rows, err = eng.Query(ctx, `SELECT name FROM items ORDER BY price DESC LIMIT 2`)
	if err != nil {
		t.Fatalf("order by desc + limit: %v", err)
	}
	if len(rows) != 2 || rows[0]["name"] != "a" || rows[1]["name"] != "c" {
		t.Fatalf("expected [a c], got %v", rows)
	}

	rows, err = eng.Query(ctx, `SELECT name FROM items ORDER BY price DESC LIMIT 2 OFFSET 1`)
	if err != nil {
		t.Fatalf("order by desc + limit + offset: %v", err)
	}
	if len(rows) != 2 || rows[0]["name"] != "c" || rows[1]["name"] != "b" {
		t.Fatalf("expected [c b], got %v", rows)
	}
}

func TestGroupByAggregate(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer VARCHAR(255), amount INT)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer, amount) VALUES (1, 'alice', 10)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer, amount) VALUES (2, 'alice', 20)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer, amount) VALUES (3, 'bob', 5)`)

	rows, err := eng.Query(ctx, `SELECT customer, COUNT(*), SUM(amount) FROM orders GROUP BY customer ORDER BY customer ASC`)
	if err != nil {
		t.Fatalf("group by: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 groups, got %d: %v", len(rows), rows)
	}
	if rows[0]["customer"] != "alice" {
		t.Fatalf("expected alice first, got %v", rows[0])
	}
	if cnt, _ := numeric(rows[0]["COUNT(*)"]); cnt != 2 {
		t.Fatalf("expected alice count 2, got %v (row: %v)", rows[0]["COUNT(*)"], rows[0])
	}
	if sum, _ := numeric(rows[0]["SUM(amount)"]); sum != 30 {
		t.Fatalf("expected alice sum 30, got %v", rows[0]["SUM(amount)"])
	}
	if cnt, _ := numeric(rows[1]["COUNT(*)"]); cnt != 1 {
		t.Fatalf("expected bob count 1, got %v", rows[1]["COUNT(*)"])
	}

	rows, err = eng.Query(ctx, `SELECT COUNT(*) FROM orders`)
	if err != nil {
		t.Fatalf("bare aggregate without group by: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 implicit-group row, got %d", len(rows))
	}
	if cnt, _ := numeric(rows[0]["COUNT(*)"]); cnt != 3 {
		t.Fatalf("expected total count 3, got %v", rows[0]["COUNT(*)"])
	}
}

func TestJoin(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(255))`)
	mustExec(t, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount INT)`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (1, 'alice')`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (2, 'bob')`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (100, 1, 30)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (101, 1, 40)`)
	// bob (id=2) has no orders — used to verify plain INNER JOIN excludes
	// him and LEFT JOIN includes him.

	rows, err := eng.Query(ctx, `SELECT customers.name, orders.amount FROM customers JOIN orders ON customers.id = orders.customer_id ORDER BY orders.amount ASC`)
	if err != nil {
		t.Fatalf("inner join: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 matched rows, got %d: %v", len(rows), rows)
	}
	if rows[0]["name"] != "alice" || rows[1]["name"] != "alice" {
		t.Fatalf("expected both matched rows to be alice, got %v", rows)
	}
	amt0, _ := numeric(rows[0]["amount"])
	amt1, _ := numeric(rows[1]["amount"])
	if amt0 != 30 || amt1 != 40 {
		t.Fatalf("expected amounts [30 40], got [%v %v]", amt0, amt1)
	}

	leftRows, err := eng.Query(ctx, `SELECT customers.name, orders.amount FROM customers LEFT JOIN orders ON customers.id = orders.customer_id`)
	if err != nil {
		t.Fatalf("left join: %v", err)
	}
	if len(leftRows) != 3 {
		t.Fatalf("expected 3 rows (2 alice orders + 1 unmatched bob), got %d: %v", len(leftRows), leftRows)
	}
	foundBob := false
	for _, r := range leftRows {
		if r["name"] == "bob" {
			foundBob = true
			if r["amount"] != nil {
				t.Fatalf("expected bob's unmatched amount to be absent/nil, got %v", r["amount"])
			}
		}
	}
	if !foundBob {
		t.Fatalf("expected bob to appear via LEFT JOIN even with no matching order, got %v", leftRows)
	}
}

func TestInSubquery(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(255), vip INT)`)
	mustExec(t, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount INT)`)
	mustExec(t, eng, `INSERT INTO customers (id, name, vip) VALUES (1, 'alice', 1)`)
	mustExec(t, eng, `INSERT INTO customers (id, name, vip) VALUES (2, 'bob', 0)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (100, 1, 30)`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (101, 2, 999)`)

	rows, err := eng.Query(ctx, `SELECT amount FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE vip = 1)`)
	if err != nil {
		t.Fatalf("in-subquery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (alice's order only), got %d: %v", len(rows), rows)
	}
	if amt, _ := numeric(rows[0]["amount"]); amt != 30 {
		t.Fatalf("expected amount 30, got %v", rows[0]["amount"])
	}

	notRows, err := eng.Query(ctx, `SELECT amount FROM orders WHERE customer_id NOT IN (SELECT id FROM customers WHERE vip = 1)`)
	if err != nil {
		t.Fatalf("not-in-subquery: %v", err)
	}
	if len(notRows) != 1 || func() float64 { v, _ := numeric(notRows[0]["amount"]); return v }() != 999 {
		t.Fatalf("expected bob's order (999) only, got %v", notRows)
	}
}

func TestCompositePrimaryKey(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE membership (org_id INT, user_id INT, role VARCHAR(255), PRIMARY KEY (org_id, user_id))`)
	mustExec(t, eng, `INSERT INTO membership (org_id, user_id, role) VALUES (1, 10, 'admin')`)
	mustExec(t, eng, `INSERT INTO membership (org_id, user_id, role) VALUES (1, 20, 'member')`)
	mustExec(t, eng, `INSERT INTO membership (org_id, user_id, role) VALUES (2, 10, 'member')`)

	rows, err := eng.Query(ctx, `SELECT role FROM membership WHERE org_id = 1 AND user_id = 10`)
	if err != nil {
		t.Fatalf("select composite pk: %v", err)
	}
	if len(rows) != 1 || rows[0]["role"] != "admin" {
		t.Fatalf("expected admin, got %v", rows)
	}

	// Same org_id, different user_id must be a distinct row (proves the
	// composite key isn't collapsing on the first column alone).
	rows, err = eng.Query(ctx, `SELECT role FROM membership WHERE org_id = 1 AND user_id = 20`)
	if err != nil || len(rows) != 1 || rows[0]["role"] != "member" {
		t.Fatalf("expected member for (1,20), got %v err=%v", rows, err)
	}

	// Duplicate composite PK must be rejected.
	_, err = eng.Exec(ctx, `INSERT INTO membership (org_id, user_id, role) VALUES (1, 10, 'other')`)
	if err == nil {
		t.Fatalf("expected duplicate composite primary key to be rejected")
	}

	all, err := eng.Query(ctx, `SELECT role FROM membership`)
	if err != nil || len(all) != 3 {
		t.Fatalf("expected 3 total rows, got %d err=%v", len(all), err)
	}
}

func TestUnion(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE a (id INT PRIMARY KEY, name VARCHAR(255))`)
	mustExec(t, eng, `CREATE TABLE b (id INT PRIMARY KEY, name VARCHAR(255))`)
	mustExec(t, eng, `INSERT INTO a (id, name) VALUES (1, 'x')`)
	mustExec(t, eng, `INSERT INTO a (id, name) VALUES (2, 'y')`)
	mustExec(t, eng, `INSERT INTO b (id, name) VALUES (1, 'y')`) // "y" duplicated across tables
	mustExec(t, eng, `INSERT INTO b (id, name) VALUES (2, 'z')`)

	rows, err := eng.Query(ctx, `SELECT name FROM a UNION SELECT name FROM b`)
	if err != nil {
		t.Fatalf("union: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 deduped rows (x,y,z), got %d: %v", len(rows), rows)
	}

	allRows, err := eng.Query(ctx, `SELECT name FROM a UNION ALL SELECT name FROM b`)
	if err != nil {
		t.Fatalf("union all: %v", err)
	}
	if len(allRows) != 4 {
		t.Fatalf("expected 4 rows with duplicates kept, got %d: %v", len(allRows), allRows)
	}
}

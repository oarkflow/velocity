package sql

import (
	"context"
	stdsql "database/sql"
	"testing"
)

// TestLeftJoin_UnmatchedRowHasNilValuedRightColumns proves the fix: an
// unmatched LEFT JOIN row must have every right-table column PRESENT (with
// a nil value), not simply absent from the map — the prior behavior. A
// plain `row["col"] != nil` check can't distinguish "absent" from
// "present and nil" (both read back as the zero value from a Go map), so
// this asserts presence explicitly via the two-value map form.
func TestLeftJoin_UnmatchedRowHasNilValuedRightColumns(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(255))`)
	mustExec(t, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount INT)`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (1, 'alice')`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (2, 'bob')`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (100, 1, 30)`)

	rows, err := eng.Query(ctx, `SELECT * FROM customers LEFT JOIN orders ON customers.id = orders.customer_id`)
	if err != nil {
		t.Fatalf("left join: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (1 matched alice + 1 unmatched bob), got %d: %v", len(rows), rows)
	}
	for _, r := range rows {
		if r["name"] == "bob" {
			v, present := r["amount"]
			if !present {
				t.Fatalf("bob's unmatched row is missing the 'amount' key entirely, want present-with-nil: %v", r)
			}
			if v != nil {
				t.Fatalf("bob's unmatched 'amount' should be nil, got %v", v)
			}
			// Every column orders declares must be present, not just the
			// one this test happens to check by name.
			for _, col := range []string{"id", "customer_id", "amount"} {
				if _, ok := r[col]; !ok {
					t.Fatalf("bob's unmatched row is missing right-table column %q entirely", col)
				}
			}
		}
	}
}

// TestLeftJoin_NullRoundTripsThroughDatabaseSQL proves the SAME nil-valued
// column survives the stdlib database/sql adapter as a real SQL NULL,
// scannable into a nullable target — not silently dropped or erroring.
func TestLeftJoin_NullRoundTripsThroughDatabaseSQL(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(255))`)
	mustExec(t, eng, `CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount INT)`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (1, 'alice')`)
	mustExec(t, eng, `INSERT INTO customers (id, name) VALUES (2, 'bob')`)
	mustExec(t, eng, `INSERT INTO orders (id, customer_id, amount) VALUES (100, 1, 30)`)

	db, err := Open(eng)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT name, amount FROM customers LEFT JOIN orders ON customers.id = orders.customer_id ORDER BY name`)
	if err != nil {
		t.Fatalf("QueryContext: %v", err)
	}
	defer rows.Close()

	var got []struct {
		name   string
		amount stdsql.NullInt64
	}
	for rows.Next() {
		var name string
		var amount stdsql.NullInt64
		if err := rows.Scan(&name, &amount); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got = append(got, struct {
			name   string
			amount stdsql.NullInt64
		}{name, amount})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got), got)
	}
	for _, g := range got {
		switch g.name {
		case "alice":
			if !g.amount.Valid || g.amount.Int64 != 30 {
				t.Fatalf("alice: expected amount=30 valid, got %+v", g.amount)
			}
		case "bob":
			if g.amount.Valid {
				t.Fatalf("bob: expected NULL amount, got valid %d", g.amount.Int64)
			}
		default:
			t.Fatalf("unexpected row name %q", g.name)
		}
	}
}

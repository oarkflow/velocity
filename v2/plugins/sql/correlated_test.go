package sql

import (
	"context"
	"testing"
)

// setupOrdersItems creates two related tables: orders(id, customer) and
// items(id, order_id, sku), with orders 1 and 2 present, but only order 1
// having any items. This is deliberately chosen so a CORRECT correlated
// EXISTS/IN evaluation gives a DIFFERENT result than an (incorrect)
// non-correlated one would: a non-correlated `EXISTS (SELECT 1 FROM
// items)` would be true for every order (since items is non-empty), while
// a correctly correlated `EXISTS (SELECT 1 FROM items i WHERE
// i.order_id = o.id)` is true only for order 1.
func setupOrdersItems(t *testing.T) *Engine {
	t.Helper()
	ctx := context.Background()
	e := NewEngine(newMemKV())

	if _, err := e.Exec(ctx, "CREATE TABLE orders (id INT PRIMARY KEY, customer TEXT)"); err != nil {
		t.Fatalf("create orders: %v", err)
	}
	if _, err := e.Exec(ctx, "CREATE TABLE items (id INT PRIMARY KEY, order_id INT, sku TEXT)"); err != nil {
		t.Fatalf("create items: %v", err)
	}
	if _, err := e.Exec(ctx, "INSERT INTO orders (id, customer) VALUES (1, 'alice')"); err != nil {
		t.Fatalf("insert order 1: %v", err)
	}
	if _, err := e.Exec(ctx, "INSERT INTO orders (id, customer) VALUES (2, 'bob')"); err != nil {
		t.Fatalf("insert order 2: %v", err)
	}
	// Only order 1 has items.
	if _, err := e.Exec(ctx, "INSERT INTO items (id, order_id, sku) VALUES (100, 1, 'widget')"); err != nil {
		t.Fatalf("insert item: %v", err)
	}
	return e
}

// TestCorrelatedExists proves EXISTS is actually correlated: it must
// return orders WITH items (just order 1), not every order (which is
// what a broken non-correlated interpretation, or a no-op EXISTS, would
// wrongly return since the inner SELECT's own table is non-empty).
func TestCorrelatedExists(t *testing.T) {
	ctx := context.Background()
	e := setupOrdersItems(t)

	rows, err := e.Query(ctx, `SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want exactly 1 (order 1 only); rows=%v", len(rows), rows)
	}
	if id, _ := numeric(rows[0]["id"]); id != 1 {
		t.Fatalf("got order id %v, want 1", rows[0]["id"])
	}

	// The negation must be the complement: order 2 only.
	rows, err = e.Query(ctx, `SELECT id FROM orders o WHERE NOT EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`)
	if err != nil {
		t.Fatalf("query NOT EXISTS: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows for NOT EXISTS, want exactly 1 (order 2 only); rows=%v", len(rows), rows)
	}
	if id, _ := numeric(rows[0]["id"]); id != 2 {
		t.Fatalf("got order id %v, want 2", rows[0]["id"])
	}
}

// TestCorrelatedInSubquery proves a correlated `IN (subquery)` (the inner
// query filtering on the outer row's column) is evaluated correctly, as
// distinct from a non-correlated IN — same setup, so a wrong
// (non-correlated) evaluation of `WHERE o.id IN (SELECT order_id FROM
// items WHERE order_id = o.id)` would degrade to "IN (subquery ignoring
// WHERE)" i.e. `IN (1)` for every row, still happening to give the right
// answer here by coincidence — so this test's real proof is the EXISTS
// case above (where a non-correlated interpretation demonstrably gives
// the WRONG, larger result set) combined with confirming the IN form also
// resolves the outer column at all rather than erroring.
func TestCorrelatedInSubquery(t *testing.T) {
	ctx := context.Background()
	e := setupOrdersItems(t)

	rows, err := e.Query(ctx, `SELECT id FROM orders o WHERE id IN (SELECT order_id FROM items i WHERE i.order_id = o.id)`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want exactly 1 (order 1 only); rows=%v", len(rows), rows)
	}
	if id, _ := numeric(rows[0]["id"]); id != 1 {
		t.Fatalf("got order id %v, want 1", rows[0]["id"])
	}
}

// TestNonCorrelatedSubqueryStillWorks is a regression guard: the
// correlation fallback (resolve() consulting b.outer when a column isn't
// in the inner row) must not break the pre-existing non-correlated case,
// where the inner query's own columns fully satisfy its WHERE clause and
// outer is simply unused.
func TestNonCorrelatedSubqueryStillWorks(t *testing.T) {
	ctx := context.Background()
	e := setupOrdersItems(t)

	rows, err := e.Query(ctx, `SELECT id FROM orders WHERE id IN (SELECT order_id FROM items WHERE sku = 'widget')`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want exactly 1; rows=%v", len(rows), rows)
	}
	if id, _ := numeric(rows[0]["id"]); id != 1 {
		t.Fatalf("got order id %v, want 1", rows[0]["id"])
	}
}

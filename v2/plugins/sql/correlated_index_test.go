package sql

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
)

// TestCorrelatedExistsUsesIndex proves resolve()'s outer-row fallback
// (added to close the "correlated subqueries are unindexed" gap) actually
// lets extractEqualityCandidate recognize `i.order_id = o.id` as an
// indexable equality candidate, instead of forcing every correlated
// EXISTS/IN onto the full-scan path. Asserts on the same white-box
// counters index_test.go already uses (a call-count assertion, not a
// timing-based one, per that file's own documented rationale).
func TestCorrelatedExistsUsesIndex(t *testing.T) {
	ctx := context.Background()
	e := setupOrdersItems(t)

	before := loadIndexedLookups()
	rows, err := e.Query(ctx, `SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	// setupOrdersItems creates 2 orders, so the correlated inner query
	// (items WHERE i.order_id = o.id) runs once per outer row: 2 indexed
	// lookups, one per order — not a full table scan of items for either.
	if got := loadIndexedLookups(); got != before+2 {
		t.Fatalf("expected exactly 2 indexed lookups (one per outer row) for the correlated EXISTS's inner query, count went %d -> %d", before, got)
	}
}

// TestCorrelatedIndex_MatchesFullScanUnderMixedWrites is the correctness
// safety net: build a table pair with DUPLICATE order_id values (so a
// subtly wrong index — e.g. one that returns only the first match, or a
// stale bucket after an UPDATE — would plausibly diverge from a correct
// full scan), interleave INSERT/UPDATE/DELETE, and confirm the indexed
// correlated-EXISTS result set is IDENTICAL to an independently-computed
// brute-force ground truth after every mutation.
func TestCorrelatedIndex_MatchesFullScanUnderMixedWrites(t *testing.T) {
	ctx := context.Background()
	e := NewEngine(newMemKV())

	must := func(query string) {
		t.Helper()
		if _, err := e.Exec(ctx, query); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}
	must(`CREATE TABLE orders (id INT PRIMARY KEY, customer TEXT)`)
	must(`CREATE TABLE items (id INT PRIMARY KEY, order_id INT, sku TEXT)`)

	// 30 orders; items with duplicate order_id values (multiple items per
	// order) so a bucket holds more than one PK.
	for i := 1; i <= 30; i++ {
		must(fmt.Sprintf(`INSERT INTO orders (id, customer) VALUES (%d, 'customer-%d')`, i, i))
	}
	itemID := 1000
	insertItem := func(orderID int) {
		must(fmt.Sprintf(`INSERT INTO items (id, order_id, sku) VALUES (%d, %d, 'sku-%d')`, itemID, orderID, itemID))
		itemID++
	}
	// Orders 1..10 get 2 items each (duplicate order_id bucket); 11..20 get
	// exactly 1; 21..30 get none.
	for o := 1; o <= 10; o++ {
		insertItem(o)
		insertItem(o)
	}
	for o := 11; o <= 20; o++ {
		insertItem(o)
	}

	bruteForceOrdersWithItems := func() map[int]bool {
		orderRows, err := e.Query(ctx, `SELECT id FROM orders`)
		if err != nil {
			t.Fatalf("brute orders: %v", err)
		}
		itemRows, err := e.Query(ctx, `SELECT order_id FROM items`)
		if err != nil {
			t.Fatalf("brute items: %v", err)
		}
		haveItem := map[int]bool{}
		for _, r := range itemRows {
			if v, ok := numeric(r["order_id"]); ok {
				haveItem[int(v)] = true
			}
		}
		want := map[int]bool{}
		for _, r := range orderRows {
			if v, ok := numeric(r["id"]); ok && haveItem[int(v)] {
				want[int(v)] = true
			}
		}
		return want
	}

	indexedOrdersWithItems := func() map[int]bool {
		rows, err := e.Query(ctx, `SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`)
		if err != nil {
			t.Fatalf("indexed query: %v", err)
		}
		got := map[int]bool{}
		for _, r := range rows {
			if v, ok := numeric(r["id"]); ok {
				got[int(v)] = true
			}
		}
		return got
	}

	assertMatch := func(step string) {
		t.Helper()
		want, got := bruteForceOrdersWithItems(), indexedOrdersWithItems()
		if len(want) != len(got) {
			t.Fatalf("%s: got %d orders-with-items, want %d (got=%v want=%v)", step, len(got), len(want), got, want)
		}
		for id := range want {
			if !got[id] {
				t.Fatalf("%s: indexed result missing order %d that brute-force found (got=%v want=%v)", step, id, got, want)
			}
		}
	}
	assertMatch("initial")

	// UPDATE: move item 1000 (originally order 1) to order 21, which
	// previously had zero items — must now show up as having items, and
	// order 1 must still show up (its duplicate sibling item remains).
	must(`UPDATE items SET order_id = 21 WHERE id = 1000`)
	assertMatch("after UPDATE moving an item to a previously-empty order")

	// DELETE: remove BOTH of order 1's items — order 1 must now
	// disappear from the result (proving the index doesn't leave a stale
	// entry after every referencing item is gone).
	must(`DELETE FROM items WHERE order_id = 1`)
	assertMatch("after DELETE removing an order's only remaining items")

	// INSERT: give order 25 (previously empty) its first item.
	insertItem(25)
	assertMatch("after INSERT giving a previously-empty order its first item")
}

// BenchmarkCorrelatedExists reports a real before/after number for the
// SAME query against the SAME data: disableOuterIndexProbe=1 reverts to
// the pre-fix behavior (every correlated condition forced onto the
// full-scan path via extractEqualityCandidate always failing to resolve
// the outer reference), disableOuterIndexProbe=0 is the real, current,
// indexed behavior.
func BenchmarkCorrelatedExists(b *testing.B) {
	ctx := context.Background()
	e := NewEngine(newMemKV())
	if _, err := e.Exec(ctx, `CREATE TABLE orders (id INT PRIMARY KEY, customer TEXT)`); err != nil {
		b.Fatal(err)
	}
	if _, err := e.Exec(ctx, `CREATE TABLE items (id INT PRIMARY KEY, order_id INT, sku TEXT)`); err != nil {
		b.Fatal(err)
	}
	// 800 rows is enough to make the O(n*m) unindexed path's cost clearly
	// visible without the benchmark itself taking minutes to run (the
	// "before" sub-benchmark is a genuine full inner-table scan PER OUTER
	// ROW, so total work is quadratic in n).
	const n = 800
	for i := 0; i < n; i++ {
		if _, err := e.Exec(ctx, fmt.Sprintf(`INSERT INTO orders (id, customer) VALUES (%d, 'c%d')`, i, i)); err != nil {
			b.Fatal(err)
		}
		// Every order gets exactly one item, so the correlated EXISTS
		// always finds a match — this exercises the real lookup cost, not
		// a best-case immediate-empty-result shortcut.
		if _, err := e.Exec(ctx, fmt.Sprintf(`INSERT INTO items (id, order_id, sku) VALUES (%d, %d, 'sku%d')`, i, i, i)); err != nil {
			b.Fatal(err)
		}
	}
	const query = `SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`

	b.Run("before_unindexed_full_scan", func(b *testing.B) {
		atomic.StoreInt32(&disableOuterIndexProbe, 1)
		defer atomic.StoreInt32(&disableOuterIndexProbe, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Query(ctx, query); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("after_indexed", func(b *testing.B) {
		atomic.StoreInt32(&disableOuterIndexProbe, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := e.Query(ctx, query); err != nil {
				b.Fatal(err)
			}
		}
	})
}

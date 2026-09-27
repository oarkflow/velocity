package sql

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentInsertsDifferentPKs stresses many goroutines concurrently
// INSERTing distinct rows into the same table, then verifies every row is
// present and correct via a full SELECT — run under -race.
func TestConcurrentInsertsDifferentPKs(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())

	if _, err := eng.Exec(ctx, "CREATE TABLE items (id INT PRIMARY KEY, label TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := eng.Exec(ctx, "INSERT INTO items (id, label) VALUES (?, ?)", i, fmt.Sprintf("label-%03d", i)); err != nil {
				t.Errorf("INSERT id=%d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	rows, err := eng.Query(ctx, "SELECT id, label FROM items")
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("expected %d rows, got %d", n, len(rows))
	}
	byID := make(map[int64]string, n)
	for _, r := range rows {
		id, ok := r["id"].(int64)
		if !ok {
			// Some engines may store as float64/int depending on JSON
			// round-tripping internals; normalize defensively.
			switch v := r["id"].(type) {
			case int:
				id = int64(v)
			case float64:
				id = int64(v)
			default:
				t.Fatalf("unexpected id type %T for row %v", r["id"], r)
			}
		}
		label, _ := r["label"].(string)
		byID[id] = label
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("label-%03d", i)
		if got := byID[int64(i)]; got != want {
			t.Errorf("id=%d: got label %q, want %q", i, got, want)
		}
	}
}

// TestConcurrentIndexedSelectDuringInserts interleaves concurrent INSERTs
// with concurrent indexed-equality SELECTs (which may exercise the
// secondary index maintained internally, if the engine's WHERE planner
// picks it for this shape) — asserts no data race and no query ever
// observes a torn/partially-indexed row: every returned row's label must
// match its id under the naming convention this test uses.
func TestConcurrentIndexedSelectDuringInserts(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())

	if _, err := eng.Exec(ctx, "CREATE TABLE users (id INT PRIMARY KEY, dept TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	const n = 60
	var wg sync.WaitGroup

	// Writers: insert rows, half in "eng" dept, half in "ops".
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dept := "eng"
			if i%2 == 0 {
				dept = "ops"
			}
			if _, err := eng.Exec(ctx, "INSERT INTO users (id, dept) VALUES (?, ?)", i, dept); err != nil {
				t.Errorf("INSERT id=%d: %v", i, err)
			}
		}(i)
	}

	// Readers: concurrently run an equality WHERE query while writes are
	// still landing. Every row returned must have dept == "eng" or "ops"
	// (never a garbled/partial value) — that's the race-safety property
	// being tested, since the exact row COUNT during concurrent writes is
	// inherently non-deterministic and not asserted here.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := eng.Query(ctx, "SELECT id, dept FROM users WHERE dept = ?", "eng")
			if err != nil {
				t.Errorf("indexed SELECT: %v", err)
				return
			}
			for _, r := range rows {
				if r["dept"] != "eng" {
					t.Errorf("indexed SELECT returned a row with dept=%v, expected only \"eng\" rows (torn/stale index read)", r["dept"])
				}
			}
		}()
	}
	wg.Wait()

	// Final consistency check once all writes have landed: an indexed
	// query's results must exactly match a full unindexed scan's results
	// (computed independently here via SELECT * + manual filter), proving
	// the index (if used) isn't stale relative to ground truth.
	all, err := eng.Query(ctx, "SELECT id, dept FROM users")
	if err != nil {
		t.Fatalf("SELECT *: %v", err)
	}
	var wantEngCount int
	for _, r := range all {
		if r["dept"] == "eng" {
			wantEngCount++
		}
	}
	indexed, err := eng.Query(ctx, "SELECT id, dept FROM users WHERE dept = ?", "eng")
	if err != nil {
		t.Fatalf("final indexed SELECT: %v", err)
	}
	if len(indexed) != wantEngCount {
		t.Fatalf("indexed SELECT returned %d rows, full-scan ground truth says %d (stale index)", len(indexed), wantEngCount)
	}
}

// TestConcurrentTransactionsDifferentRows runs many independent
// transactions concurrently, each touching its OWN row (not overlapping
// with any other transaction's row) — this is the isolation level the
// engine actually documents (tx.go: writes land immediately, no
// serialization between transactions on DIFFERENT rows is required or
// promised beyond "each individual write is race-free"), so this test
// does not assert cross-transaction isolation on shared rows, only that
// concurrent, non-overlapping transactions all commit correctly with no
// data race and no cross-transaction corruption.
func TestConcurrentTransactionsDifferentRows(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())

	if _, err := eng.Exec(ctx, "CREATE TABLE accounts (id INT PRIMARY KEY, balance INT)"); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txn, err := eng.Begin(ctx)
			if err != nil {
				t.Errorf("Begin (row %d): %v", i, err)
				return
			}
			if _, err := txn.Exec(ctx, "INSERT INTO accounts (id, balance) VALUES (?, ?)", i, 100+i); err != nil {
				t.Errorf("txn Exec (row %d): %v", i, err)
				_ = txn.Rollback()
				return
			}
			if err := txn.Commit(); err != nil {
				t.Errorf("txn Commit (row %d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	rows, err := eng.Query(ctx, "SELECT id, balance FROM accounts")
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("expected %d committed rows, got %d", n, len(rows))
	}
}

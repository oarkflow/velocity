package sql

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// TestIndexedEquality_UsesIndexNotFullScan proves an equality WHERE on a
// non-PK column goes through the secondary index (loadIndexedLookups
// increases) rather than scanTable (loadFullTableScans does not), while
// still returning the correct rows.
func TestIndexedEquality_UsesIndexNotFullScan(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE users (id INT PRIMARY KEY, city VARCHAR(255))`)
	mustExec(t, eng, `INSERT INTO users (id, city) VALUES (1, 'reno')`)
	mustExec(t, eng, `INSERT INTO users (id, city) VALUES (2, 'nyc')`)
	mustExec(t, eng, `INSERT INTO users (id, city) VALUES (3, 'reno')`)

	before := loadIndexedLookups()
	scansBefore := loadFullTableScans()

	rows, err := eng.Query(ctx, `SELECT id FROM users WHERE city = ?`, "reno")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if loadIndexedLookups() != before+1 {
		t.Fatalf("expected an indexed lookup to have run, count unchanged (%d)", loadIndexedLookups())
	}
	if loadFullTableScans() != scansBefore {
		t.Fatalf("expected NO full table scan, but scanTable ran (%d -> %d)", scansBefore, loadFullTableScans())
	}
	ids := idSet(rows)
	if len(ids) != 2 || !ids[1] || !ids[3] {
		t.Fatalf("expected ids {1,3} for city=reno, got %v", ids)
	}
}

// TestIndexConsistency_UpdateAndDelete proves the index is kept correct
// across UPDATE (old value stops matching, new value starts) and DELETE
// (the deleted row stops matching entirely) — not just correct at INSERT
// time.
func TestIndexConsistency_UpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE users (id INT PRIMARY KEY, city VARCHAR(255))`)
	mustExec(t, eng, `INSERT INTO users (id, city) VALUES (1, 'reno')`)
	mustExec(t, eng, `INSERT INTO users (id, city) VALUES (2, 'nyc')`)

	// UPDATE: city changes reno -> nyc for id=1.
	if _, err := eng.Exec(ctx, `UPDATE users SET city = 'nyc' WHERE id = 1`); err != nil {
		t.Fatalf("update: %v", err)
	}
	rowsReno, err := eng.Query(ctx, `SELECT id FROM users WHERE city = ?`, "reno")
	if err != nil {
		t.Fatalf("query reno: %v", err)
	}
	if len(rowsReno) != 0 {
		t.Fatalf("expected no rows for city=reno after update, got %v", rowsReno)
	}
	rowsNYC, err := eng.Query(ctx, `SELECT id FROM users WHERE city = ?`, "nyc")
	if err != nil {
		t.Fatalf("query nyc: %v", err)
	}
	ids := idSet(rowsNYC)
	if len(ids) != 2 || !ids[1] || !ids[2] {
		t.Fatalf("expected ids {1,2} for city=nyc after update, got %v", ids)
	}

	// DELETE: id=2 removed entirely.
	if _, err := eng.Exec(ctx, `DELETE FROM users WHERE id = 2`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rowsNYC2, err := eng.Query(ctx, `SELECT id FROM users WHERE city = ?`, "nyc")
	if err != nil {
		t.Fatalf("query nyc after delete: %v", err)
	}
	ids2 := idSet(rowsNYC2)
	if len(ids2) != 1 || !ids2[1] {
		t.Fatalf("expected only id {1} for city=nyc after deleting id=2, got %v", ids2)
	}
}

func idSet(rows []api.Row) map[int64]bool {
	out := make(map[int64]bool, len(rows))
	for _, r := range rows {
		id, _ := numeric(r["id"])
		out[int64(id)] = true
	}
	return out
}

// TestIndexVsFullScan_CorrectnessUnderMixedWrites is the correctness
// safety net for the whole indexing feature: build a table large enough
// (500+ rows, several duplicate values per indexed column) that a stale or
// buggy index would plausibly show wrong results, run a realistic mix of
// INSERT/UPDATE/DELETE against it, then verify an INDEXED equality query's
// results EXACTLY match a FORCED full-scan computed independently in this
// test (not by calling the engine's own full-scan path, which could share
// a bug with the index path — by walking the same rows via a raw SELECT *
// and filtering in Go).
func TestIndexVsFullScan_CorrectnessUnderMixedWrites(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	mustExec(t, eng, `CREATE TABLE items (id INT PRIMARY KEY, bucket INT)`)

	const n = 600
	const numBuckets = 7
	for i := 0; i < n; i++ {
		if _, err := eng.Exec(ctx, `INSERT INTO items (id, bucket) VALUES (?, ?)`, i, i%numBuckets); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// Mixed writes: update every 3rd row into a different bucket, delete
	// every 11th row.
	for i := 0; i < n; i++ {
		switch {
		case i%11 == 0:
			if _, err := eng.Exec(ctx, `DELETE FROM items WHERE id = ?`, i); err != nil {
				t.Fatalf("delete %d: %v", i, err)
			}
		case i%3 == 0:
			newBucket := (i + 1) % numBuckets
			if _, err := eng.Exec(ctx, `UPDATE items SET bucket = ? WHERE id = ?`, newBucket, i); err != nil {
				t.Fatalf("update %d: %v", i, err)
			}
		}
	}

	// Ground truth: fetch EVERY row via SELECT * (no WHERE at all, so this
	// never hits the indexed-candidate path — see selectRowsOne, which
	// only takes that path when stmt.Where != nil), then filter in Go.
	all, err := eng.Query(ctx, `SELECT id, bucket FROM items`)
	if err != nil {
		t.Fatalf("select all: %v", err)
	}

	for bucket := 0; bucket < numBuckets; bucket++ {
		var wantIDs []int64
		for _, r := range all {
			b, _ := numeric(r["bucket"])
			if int(b) == bucket {
				id, _ := numeric(r["id"])
				wantIDs = append(wantIDs, int64(id))
			}
		}
		sort.Slice(wantIDs, func(i, j int) bool { return wantIDs[i] < wantIDs[j] })

		got, err := eng.Query(ctx, `SELECT id FROM items WHERE bucket = ?`, bucket)
		if err != nil {
			t.Fatalf("indexed query bucket=%d: %v", bucket, err)
		}
		var gotIDs []int64
		for _, r := range got {
			id, _ := numeric(r["id"])
			gotIDs = append(gotIDs, int64(id))
		}
		sort.Slice(gotIDs, func(i, j int) bool { return gotIDs[i] < gotIDs[j] })

		if fmt.Sprint(gotIDs) != fmt.Sprint(wantIDs) {
			t.Fatalf("bucket=%d: indexed query returned %v, full-scan ground truth says %v", bucket, gotIDs, wantIDs)
		}
	}
}

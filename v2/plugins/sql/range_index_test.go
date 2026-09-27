package sql

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// TestSortableEncoding_PreservesOrder is the correctness safety net for
// the whole range index: if this encoding were subtly wrong (e.g. -5
// sorting after 3), every range query built on top of it would silently
// return wrong results, which is worse than the plain full-scan behavior
// this feature replaces.
func TestSortableEncoding_PreservesOrder(t *testing.T) {
	floats := []float64{-1000000, -12345.678, -1, -0.5, 0, 0.5, 1, 2, 3, 12345.678, 1000000}
	// Shuffle a copy, encode, sort by encoded bytes, and confirm the
	// decoded order matches the original sorted order exactly.
	shuffled := append([]float64{}, floats...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	type pair struct {
		orig    float64
		encoded []byte
	}
	pairs := make([]pair, len(shuffled))
	for i, f := range shuffled {
		pairs[i] = pair{orig: f, encoded: encodeSortableFloat(f)}
	}
	sort.Slice(pairs, func(i, j int) bool {
		for k := 0; k < len(pairs[i].encoded); k++ {
			if pairs[i].encoded[k] != pairs[j].encoded[k] {
				return pairs[i].encoded[k] < pairs[j].encoded[k]
			}
		}
		return false
	})
	for i, p := range pairs {
		if p.orig != floats[i] {
			t.Fatalf("byte-sorted order mismatch at index %d: got %v, want %v (full: %v)", i, p.orig, floats[i], pairs)
		}
	}

	// Round-trip decode check.
	for _, f := range floats {
		got := decodeSortableFloat(encodeSortableFloat(f))
		if got != f {
			t.Fatalf("decodeSortableFloat(encodeSortableFloat(%v)) = %v, want %v", f, got, f)
		}
	}

	// String ordering, including the specific "proper prefix with a
	// lower-byte-value continuation" case that a naive separator scheme
	// gets wrong (see range_index.go's package doc comment): "a" vs "a."
	// — "." (0x2E) is less than "/" (0x2F), the kind of separator a naive
	// scheme might use, so this is exactly the case that would break
	// under naive concatenation.
	strs := []string{"", "a", "a.", "a/", "aa", "ab", "b", "b\x00c", "b\x00\x00d", "\x00", "\x00\x00"}
	shuffledS := append([]string{}, strs...)
	rand.Shuffle(len(shuffledS), func(i, j int) { shuffledS[i], shuffledS[j] = shuffledS[j], shuffledS[i] })
	type spair struct {
		orig    string
		encoded []byte
	}
	spairs := make([]spair, len(shuffledS))
	for i, s := range shuffledS {
		spairs[i] = spair{orig: s, encoded: encodeSortableString(s)}
	}
	sort.Slice(spairs, func(i, j int) bool {
		a, b := spairs[i].encoded, spairs[j].encoded
		n := len(a)
		if len(b) < n {
			n = len(b)
		}
		for k := 0; k < n; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	sortedWant := append([]string{}, strs...)
	sort.Strings(sortedWant)
	for i, p := range spairs {
		if p.orig != sortedWant[i] {
			gotOrder := make([]string, len(spairs))
			for j, sp := range spairs {
				gotOrder[j] = sp.orig
			}
			t.Fatalf("string byte-sorted order mismatch at index %d: got %q, want %q (full got: %v, want: %v)", i, p.orig, sortedWant[i], gotOrder, sortedWant)
		}
	}

	// Round-trip decode check for strings, including embedded NULs.
	for _, s := range strs {
		enc := encodeSortableString(s)
		got, consumed, ok := decodeSortableString(enc)
		if !ok {
			t.Fatalf("decodeSortableString(encodeSortableString(%q)) failed to decode", s)
		}
		if got != s {
			t.Fatalf("decodeSortableString(encodeSortableString(%q)) = %q, want %q", s, got, s)
		}
		if consumed != len(enc) {
			t.Fatalf("decodeSortableString(%q) consumed %d bytes, want %d (full encoded length)", s, consumed, len(enc))
		}
	}
}

func setupRangeTable(t *testing.T, eng *Engine) {
	t.Helper()
	ctx := context.Background()
	if _, err := eng.Exec(ctx, `CREATE TABLE items (id INT PRIMARY KEY, age INT, name VARCHAR(255))`); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	// Deliberately include negative numbers, zero, and duplicates, per
	// directive's correctness bar.
	ages := []int{-10, -5, 0, 0, 3, 3, 10, 25, 40, 50, 50, 51, 75, 99, -1}
	for i, age := range ages {
		q := fmt.Sprintf(`INSERT INTO items (id, age, name) VALUES (%d, %d, 'item-%d')`, i, age, i)
		if _, err := eng.Exec(ctx, q); err != nil {
			t.Fatalf("INSERT %d: %v", i, err)
		}
	}
}

// bruteForceFilter re-implements the range predicate directly in Go
// (independent of the engine's own indexed path) as ground truth to diff
// against — this is what actually proves the index isn't silently wrong,
// not just "doesn't error."
func bruteForceAges(ages []int, pred func(int) bool) map[int]bool {
	out := map[int]bool{}
	for i, a := range ages {
		if pred(a) {
			out[i] = true
		}
	}
	return out
}

func TestRangeQuery_MatchesFullScanExactly(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	setupRangeTable(t, eng)
	ages := []int{-10, -5, 0, 0, 3, 3, 10, 25, 40, 50, 50, 51, 75, 99, -1}

	cases := []struct {
		name  string
		query string
		pred  func(int) bool
	}{
		{"gt", `SELECT id FROM items WHERE age > 50`, func(a int) bool { return a > 50 }},
		{"gte", `SELECT id FROM items WHERE age >= 50`, func(a int) bool { return a >= 50 }},
		{"lt", `SELECT id FROM items WHERE age < 0`, func(a int) bool { return a < 0 }},
		{"lte", `SELECT id FROM items WHERE age <= 0`, func(a int) bool { return a <= 0 }},
		{"between", `SELECT id FROM items WHERE age BETWEEN 0 AND 40`, func(a int) bool { return a >= 0 && a <= 40 }},
		{"and-merge", `SELECT id FROM items WHERE age > -5 AND age < 51`, func(a int) bool { return a > -5 && a < 51 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := eng.Query(ctx, tc.query)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			got := map[int]bool{}
			for _, r := range rows {
				id := int(r["id"].(float64))
				got[id] = true
			}
			want := bruteForceAges(ages, tc.pred)
			if len(got) != len(want) {
				t.Fatalf("%s: got %d rows, want %d (got=%v want=%v)", tc.name, len(got), len(want), got, want)
			}
			for id := range want {
				if !got[id] {
					t.Fatalf("%s: missing expected row id=%d (age=%d)", tc.name, id, ages[id])
				}
			}
		})
	}
}

func TestLikePrefix_UsesRangeIndexAndMatchesFullScan(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	if _, err := eng.Exec(ctx, `CREATE TABLE docs (id INT PRIMARY KEY, title VARCHAR(255))`); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	titles := []string{"apple pie", "apple tart", "banana split", "applesauce", "cherry pie"}
	for i, ti := range titles {
		if _, err := eng.Exec(ctx, fmt.Sprintf(`INSERT INTO docs (id, title) VALUES (%d, '%s')`, i, ti)); err != nil {
			t.Fatalf("INSERT: %v", err)
		}
	}
	before := loadRangeIndexedLookups()
	rows, err := eng.Query(ctx, `SELECT id FROM docs WHERE title LIKE 'apple%'`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if loadRangeIndexedLookups() != before+1 {
		t.Fatalf("expected LIKE 'apple%%' to use the range index, indexed-lookup counter did not increment")
	}
	got := map[int]bool{}
	for _, r := range rows {
		got[int(r["id"].(float64))] = true
	}
	want := map[int]bool{0: true, 1: true, 3: true} // "apple pie", "apple tart", "applesauce"
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("missing expected id=%d in %v", id, got)
		}
	}
}

func TestRangeIndex_ConsistentUnderUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	if _, err := eng.Exec(ctx, `CREATE TABLE t (id INT PRIMARY KEY, val INT)`); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	if _, err := eng.Exec(ctx, `INSERT INTO t (id, val) VALUES (1, 10)`); err != nil {
		t.Fatalf("INSERT: %v", err)
	}

	assertCount := func(query string, want int) {
		t.Helper()
		rows, err := eng.Query(ctx, query)
		if err != nil {
			t.Fatalf("Query(%q): %v", query, err)
		}
		if len(rows) != want {
			t.Fatalf("Query(%q) = %d rows, want %d", query, len(rows), want)
		}
	}

	assertCount(`SELECT id FROM t WHERE val > 5`, 1)
	assertCount(`SELECT id FROM t WHERE val > 50`, 0)

	if _, err := eng.Exec(ctx, `UPDATE t SET val = 100 WHERE id = 1`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}
	// Old value (10) must no longer match; new value (100) must.
	assertCount(`SELECT id FROM t WHERE val > 5 AND val < 20`, 0)
	assertCount(`SELECT id FROM t WHERE val > 50`, 1)

	if _, err := eng.Exec(ctx, `DELETE FROM t WHERE id = 1`); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	assertCount(`SELECT id FROM t WHERE val > 50`, 0)
}

// TestRangeQuery_TouchesFewerRowsThanFullTableWhenSelective is the
// performance sanity check: on a table with a clearly selective
// predicate, the number of ROWS actually fetched (addRangeRowsFetched)
// must be close to the matching count, not the whole table — proving the
// index narrows candidates rather than silently falling through to a
// full scan while still returning correct results.
func TestRangeQuery_TouchesFewerRowsThanFullTableWhenSelective(t *testing.T) {
	ctx := context.Background()
	eng := NewEngine(newMemKV())
	if _, err := eng.Exec(ctx, `CREATE TABLE big (id INT PRIMARY KEY, score INT)`); err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}
	const n = 500
	for i := 0; i < n; i++ {
		if _, err := eng.Exec(ctx, fmt.Sprintf(`INSERT INTO big (id, score) VALUES (%d, %d)`, i, i)); err != nil {
			t.Fatalf("INSERT %d: %v", i, err)
		}
	}
	before := loadRangeRowsFetched()
	rows, err := eng.Query(ctx, `SELECT id FROM big WHERE score > 495`) // matches exactly 4 rows: 496..499
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	touched := loadRangeRowsFetched() - before
	if touched > 10 { // small overhead allowance, but nowhere near n=500
		t.Fatalf("range query touched %d rows for a 4-row-selective predicate on a %d-row table — index did not narrow candidates", touched, n)
	}
}

package lsm

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// scanAll drains an iterator into a key list.
func scanAll(t *testing.T, it api.Iterator) []string {
	t.Helper()
	defer it.Close()
	var got []string
	for it.Next() {
		got = append(got, string(it.Key()))
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}

func putAll(t *testing.T, e *Engine, keys ...string) {
	t.Helper()
	ctx := context.Background()
	for _, k := range keys {
		if err := e.Put(ctx, api.Entry{Key: []byte(k), Value: []byte("v-" + k)}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestScanFrom_MatchesScanAtEveryPosition asserts ScanFrom(prefix, k) is
// exactly Scan(prefix) truncated at k, across keys that live in the memtable,
// in a flushed sstable, and in both (shadowed).
func TestScanFrom_MatchesScanAtEveryPosition(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// small flush threshold so some keys land in an sstable and later ones
	// stay in the memtable
	e.flushThreshold = 512

	var keys []string
	for i := 0; i < 60; i++ {
		keys = append(keys, fmt.Sprintf("p/%03d", i))
	}
	putAll(t, e, keys...)
	// force a flush, then add more so the two layers overlap
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	putAll(t, e, keys[30:]...) // shadow sstable entries with newer memtable writes

	it, err := e.Scan(ctx, []byte("p/"))
	if err != nil {
		t.Fatal(err)
	}
	full := scanAll(t, it)
	if len(full) != 60 {
		t.Fatalf("expected 60 keys, got %d", len(full))
	}
	if !sort.StringsAreSorted(full) {
		t.Fatalf("scan not sorted: %v", full)
	}

	// Every possible start position, plus one past the end and one below.
	starts := append([]string{""}, full...)
	starts = append(starts, "p/999")
	for _, start := range starts {
		var want []string
		for _, k := range full {
			if start == "" || k >= start {
				want = append(want, k)
			}
		}
		it, err := e.ScanFrom(ctx, []byte("p/"), []byte(start), 0)
		if err != nil {
			t.Fatal(err)
		}
		got := scanAll(t, it)
		if len(got) != len(want) {
			t.Fatalf("start=%q: got %d keys %v, want %d %v", start, len(got), got, len(want), want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("start=%q: key %d = %q, want %q", start, i, got[i], want[i])
			}
		}
	}
}

// TestScanFrom_SkipsTombstonesAndExpiry guards the interaction between the
// seek and the deleted/expired filtering: a cursor pointing at a deleted key
// must not resurface it, and must not stall the walk.
func TestScanFrom_SkipsTombstonesAndExpiry(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	e.flushThreshold = 512
	var keys []string
	for i := 0; i < 40; i++ {
		keys = append(keys, fmt.Sprintf("t/%03d", i))
	}
	putAll(t, e, keys...)
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	// tombstone in the memtable shadowing a flushed key
	if err := e.Delete(ctx, []byte("t/010")); err != nil {
		t.Fatal(err)
	}
	// an expired entry. Note a negative TTL means "no expiry" (nowExpiry maps
	// ttl <= 0 to 0), so this must be a real short TTL plus a wait.
	if err := e.Put(ctx, api.Entry{Key: []byte("t/020"), Value: []byte("gone"), TTL: 20 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	want := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "t/010" || k == "t/020" {
			continue
		}
		want = append(want, k)
	}

	for _, start := range []string{"", "t/000", "t/009", "t/010", "t/011", "t/020", "t/030"} {
		var expect []string
		for _, k := range want {
			if start == "" || k >= start {
				expect = append(expect, k)
			}
		}
		it, err := e.ScanFrom(ctx, []byte("t/"), []byte(start), 0)
		if err != nil {
			t.Fatal(err)
		}
		got := scanAll(t, it)
		if len(got) != len(expect) {
			t.Fatalf("start=%q: got %d %v, want %d %v", start, len(got), got, len(expect), expect)
		}
		for i := range got {
			if got[i] != expect[i] {
				t.Fatalf("start=%q: key %d = %q, want %q", start, i, got[i], expect[i])
			}
		}
	}
}

// TestScanFrom_PaginatedWalkEqualsSingleScan is the property the whole
// optimization exists for: walking in pages must return each key exactly
// once, in order, with no gaps or repeats at page boundaries.
func TestScanFrom_PaginatedWalkEqualsSingleScan(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	e.flushThreshold = 700
	var keys []string
	for i := 0; i < 137; i++ { // deliberately not a multiple of the page size
		keys = append(keys, fmt.Sprintf("w/%04d", i))
	}
	putAll(t, e, keys[:80]...)
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	putAll(t, e, keys[60:]...) // overlap: 60..79 now shadow the sstable

	const page = 8
	var walked []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("pagination did not terminate")
		}
		it, err := e.ScanFrom(ctx, []byte("w/"), []byte(cursor), 0)
		if err != nil {
			t.Fatal(err)
		}
		var batch []string
		next := ""
		for it.Next() {
			k := string(it.Key())
			// Per api.RangedScanner, the cursor names the next key to RETURN,
			// so a full page stops before appending its last key: that key
			// becomes the next page's first result, never a duplicate.
			if len(batch) == page {
				next = k
				break
			}
			batch = append(batch, k)
		}
		it.Close()
		walked = append(walked, batch...)
		if len(batch) < page {
			break
		}
		cursor = next
	}

	if len(walked) != len(keys) {
		t.Fatalf("paged walk returned %d keys, want %d", len(walked), len(keys))
	}
	for i, k := range keys {
		if walked[i] != k {
			t.Fatalf("paged walk[%d] = %q, want %q", i, walked[i], k)
		}
	}
}

// TestScanFrom_EmptyPrefixAndNoMatches covers the degenerate inputs.
func TestScanFrom_EmptyPrefixAndNoMatches(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	putAll(t, e, "a", "b")

	it, err := e.ScanFrom(ctx, []byte("zzz"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanAll(t, it); len(got) != 0 {
		t.Fatalf("expected no keys for unmatched prefix, got %v", got)
	}

	// empty prefix = whole keyspace, and an empty engine yields nothing
	it, err = e.ScanFrom(ctx, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanAll(t, it); len(got) != 2 {
		t.Fatalf("empty prefix should return all 2 keys, got %v", got)
	}

	empty, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	it, err = empty.ScanFrom(ctx, []byte("a"), []byte("a"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanAll(t, it); len(got) != 0 {
		t.Fatalf("empty engine returned %v", got)
	}
}

// TestScanFrom_MaxKeysBoundsThePage asserts maxKeys is an upper bound on the
// entries returned, and that truncating does not corrupt ordering.
func TestScanFrom_MaxKeysBoundsThePage(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	e.flushThreshold = 700
	var keys []string
	for i := 0; i < 50; i++ {
		keys = append(keys, fmt.Sprintf("m/%03d", i))
	}
	putAll(t, e, keys[:30]...)
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	putAll(t, e, keys[20:]...)

	for _, max := range []int{1, 2, 7, 25, 49, 50, 51, 200} {
		it, err := e.ScanFrom(ctx, []byte("m/"), nil, max)
		if err != nil {
			t.Fatal(err)
		}
		got := scanAll(t, it)
		if len(got) > max {
			t.Fatalf("max=%d returned %d keys", max, len(got))
		}
		wantN := len(keys)
		if max < wantN {
			wantN = max
		}
		if len(got) != wantN {
			t.Fatalf("max=%d: got %d keys, want %d", max, len(got), wantN)
		}
		// truncation must keep the SMALLEST keys, in order
		for i, k := range got {
			if k != keys[i] {
				t.Fatalf("max=%d: key %d = %q, want %q", max, i, k, keys[i])
			}
		}
	}

	// max <= 0 means unlimited
	it, err := e.ScanFrom(ctx, []byte("m/"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanAll(t, it); len(got) != len(keys) {
		t.Fatalf("unlimited returned %d, want %d", len(got), len(keys))
	}
}

// TestScanFrom_BoundedPagesCoverEverythingExactlyOnce is the end-to-end
// property: paginating with maxKeys=page must visit each key once, in order,
// across a keyspace that spans flushed and unflushed data — including the
// final partial page.
func TestScanFrom_BoundedPagesCoverEverythingExactlyOnce(t *testing.T) {
	ctx := context.Background()
	e, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	e.flushThreshold = 900
	var keys []string
	for i := 0; i < 101; i++ { // prime-ish, so the last page is partial
		keys = append(keys, fmt.Sprintf("z/%04d", i))
	}
	putAll(t, e, keys[:55]...)
	if err := e.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	putAll(t, e, keys[40:]...)

	const page = 10
	var walked []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("pagination did not terminate")
		}
		it, err := e.ScanFrom(ctx, []byte("z/"), []byte(cursor), page+1)
		if err != nil {
			t.Fatal(err)
		}
		var batch []string
		exhausted := true
		for it.Next() {
			k := string(it.Key())
			if len(batch) == page {
				// one key beyond the page: becomes the next cursor
				cursor = k
				exhausted = false
				break
			}
			batch = append(batch, k)
		}
		it.Close()
		walked = append(walked, batch...)
		if exhausted || len(batch) == 0 {
			break
		}
	}

	if len(walked) != len(keys) {
		t.Fatalf("paged walk returned %d keys, want %d (%v)", len(walked), len(keys), walked)
	}
	for i := range keys {
		if walked[i] != keys[i] {
			t.Fatalf("paged walk[%d] = %q, want %q", i, walked[i], keys[i])
		}
	}
}

package mem

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

func drain(t *testing.T, it api.Iterator) []string {
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

func seed(t *testing.T, e *Engine, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if err := e.Put(context.Background(), api.Entry{Key: []byte(k), Value: []byte("v-" + k)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanFromResumeAndBound(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	defer e.Close()

	var keys []string
	for i := 0; i < 100; i++ {
		keys = append(keys, fmt.Sprintf("k/%03d", i))
	}
	seed(t, e, keys...)

	full := drain(t, mustScan(t, e, ctx, "k/", "", 0))
	if len(full) != 100 {
		t.Fatalf("full scan: got %d keys, want 100", len(full))
	}
	if !sort.StringsAreSorted(full) {
		t.Fatal("full scan not sorted")
	}

	// resume at every position
	for _, start := range []string{"", "k/000", "k/050", "k/099", "k/100", "k/999"} {
		var want []string
		for _, k := range keys {
			if start == "" || k >= start {
				want = append(want, k)
			}
		}
		got := drain(t, mustScan(t, e, ctx, "k/", start, 0))
		if len(got) != len(want) {
			t.Fatalf("start=%q: got %d, want %d", start, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("start=%q: [%d]=%q want %q", start, i, got[i], want[i])
			}
		}
	}

	// bound keeps the SMALLEST keys
	for _, max := range []int{1, 5, 50, 99, 100, 101} {
		got := drain(t, mustScan(t, e, ctx, "k/", "", max))
		wantN := max
		if wantN > 100 {
			wantN = 100
		}
		if len(got) != wantN {
			t.Fatalf("max=%d: got %d, want %d", max, len(got), wantN)
		}
		for i := range got {
			if got[i] != keys[i] {
				t.Fatalf("max=%d: [%d]=%q want %q", max, i, got[i], keys[i])
			}
		}
	}

	// bounded paging covers everything exactly once
	var walked []string
	cursor := ""
	for i := 0; i < 200; i++ {
		page := 7
		got := drain(t, mustScan(t, e, ctx, "k/", cursor, page+1))
		if len(got) <= page {
			walked = append(walked, got...)
			break
		}
		walked = append(walked, got[:page]...)
		cursor = got[page]
	}
	if len(walked) != 100 {
		t.Fatalf("paged walk: got %d keys, want 100", len(walked))
	}
	for i := range keys {
		if walked[i] != keys[i] {
			t.Fatalf("paged walk[%d]=%q want %q", i, walked[i], keys[i])
		}
	}
}

func mustScan(t *testing.T, e *Engine, ctx context.Context, prefix, start string, max int) api.Iterator {
	t.Helper()
	it, err := e.ScanFrom(ctx, []byte(prefix), []byte(start), max)
	if err != nil {
		t.Fatal(err)
	}
	return it
}
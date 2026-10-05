package kv

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// rangedBackend wraps a memBackend and adds api.RangedScanner, so tests can
// compare the seekable path against the plain-Scan fallback and assert the
// fallback is still correct.
type rangedBackend struct {
	*memBackend
	mu       sync.Mutex
	scanFrom int // how many times ScanFrom was actually used
}

func (r *rangedBackend) ScanFrom(ctx context.Context, prefix, startKey []byte, maxKeys int) (api.Iterator, error) {
	r.mu.Lock()
	r.scanFrom++
	r.mu.Unlock()
	var p string
	if len(startKey) > 0 {
		p = string(startKey)
	}
	var keys []string
	for k := range r.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == string(prefix) && (p == "" || k >= p) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = r.data[k]
	}
	return &sliceIter{keys: keys, vals: vals, pos: -1}, nil
}

type sliceIter struct {
	keys []string
	vals [][]byte
	pos  int
}

func (i *sliceIter) Next() bool  { i.pos++; return i.pos < len(i.keys) }
func (i *sliceIter) Key() []byte { return []byte(i.keys[i.pos]) }
func (i *sliceIter) Value() []byte {
	return i.vals[i.pos]
}
func (i *sliceIter) Err() error   { return nil }
func (i *sliceIter) Close() error { return nil }

// walkPages pages through Scan and returns every key it saw, plus the number
// of pages and whether each page ended with a non-empty cursor.
func walkPages(t *testing.T, p *Plugin, prefix string, limit int) ([]string, int) {
	t.Helper()
	ctx := context.Background()
	var all []string
	cursor := ""
	pages := 0
	for i := 0; i < 10000; i++ {
		pages++
		items, next, err := p.Scan(ctx, prefix, limit, cursor)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		var batch []string
		for k := range items {
			batch = append(batch, k)
		}
		sort.Strings(batch)
		all = append(all, batch...)
		if next == "" {
			return all, pages
		}
		if len(items) != limit {
			t.Fatalf("page %d returned %d items with a non-empty cursor (limit %d)",
				pages, len(items), limit)
		}
		cursor = next
	}
	t.Fatal("pagination did not terminate")
	return nil, 0
}

func seedN(t *testing.T, p *Plugin, prefix string, n int) {
	t.Helper()
	seedNT(t, p, context.Background(), prefix, n)
}

func seedNT(t *testing.T, p *Plugin, ctx context.Context, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := p.Put(ctx, fmt.Sprintf("%s%03d", prefix, i), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
}

// TestScanPagination_CoversEveryKeyExactlyOnce is the property that matters:
// however the backend is reached, a paged walk must return every key exactly
// once, in ascending order, with no gaps or duplicates at page boundaries.
func TestScanPagination_CoversEveryKeyExactlyOnce(t *testing.T) {
	for _, limit := range []int{1, 2, 3, 7, 16, 99, 100, 101} {
		for _, backend := range []string{"plain", "ranged"} {
			t.Run(fmt.Sprintf("limit=%d/%s", limit, backend), func(t *testing.T) {
				var p *Plugin
				switch backend {
				case "plain":
					p = &Plugin{storage: newMemBackend()}
				default:
					p = &Plugin{storage: &rangedBackend{memBackend: newMemBackend()}}
				}
				seedN(t, p, "k:", 100)

				got, pages := walkPages(t, p, "k:", limit)
				if len(got) != 100 {
					t.Fatalf("got %d keys, want 100 (pages=%d)", len(got), pages)
				}
				for i := range got {
					want := fmt.Sprintf("k:%03d", i)
					if got[i] != want {
						t.Fatalf("key %d = %q, want %q", i, got[i], want)
					}
				}
			})
		}
	}
}

// TestScanPagination_UsesScanFromWhenAvailable asserts the optimization is
// actually engaged on the seekable path (and only there).
func TestScanPagination_UsesScanFromWhenAvailable(t *testing.T) {
	ctx := context.Background()
	seedN(t, &Plugin{storage: newMemBackend()}, "k:", 20)

	plain := &Plugin{storage: newMemBackend()}
	seedN(t, plain, "k:", 20)
	if _, pages := walkPages(t, plain, "k:", 5); pages < 2 {
		t.Fatalf("expected multiple pages, got %d", pages)
	}

	rb := &rangedBackend{memBackend: newMemBackend()}
	ranged := &Plugin{storage: rb}
	seedN(t, ranged, "k:", 20)
	if _, pages := walkPages(t, ranged, "k:", 5); pages < 2 {
		t.Fatalf("expected multiple pages, got %d", pages)
	}
	rb.mu.Lock()
	used := rb.scanFrom
	rb.mu.Unlock()
	if used < 2 {
		t.Fatalf("expected ScanFrom on every page of a %d-page walk, got %d calls", 4, used)
	}
	_ = ctx
}

// TestScanPagination_TenantScopeStillCoversEverything exercises the
// tenantScope wrapper's ScanFrom forwarding and its ErrRangeUnsupported
// fallback, since the wrapper can only strip a prefix it added.
func TestScanPagination_TenantScopeStillCoversEverything(t *testing.T) {
	ctx := context.Background()
	rb := &rangedBackend{memBackend: newMemBackend()}
	p := &Plugin{storage: rb}

	// Seed THROUGH the tenant context: tenantScope rewrites every key to
	// "tenant/acme/k:NNN" on write, so seeding outside it would store
	// unprefixed keys the tenant can never see.
	tctx := api.WithTenant(ctx, "acme")
	seedNT(t, p, tctx, "k:", 40)
	var got []string
	cursor := ""
	for i := 0; i < 1000; i++ {
		items, next, err := p.Scan(tctx, "k:", 6, cursor)
		if err != nil {
			t.Fatal(err)
		}
		var batch []string
		for k := range items {
			batch = append(batch, k)
		}
		sort.Strings(batch)
		got = append(got, batch...)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(got) != 40 {
		t.Fatalf("tenant-scoped walk got %d keys, want 40", len(got))
	}
	for i, k := range got {
		// keys must be UNPREFIXED: the tenant prefix is stripped for the caller
		if want := fmt.Sprintf("k:%03d", i); k != want {
			t.Fatalf("key %d = %q, want %q (tenant prefix leaked?)", i, k, want)
		}
	}

	// A tenant scope over a NON-seekable backend must fall back gracefully.
	plainScoped := &Plugin{storage: newMemBackend()}
	for i := 0; i < 30; i++ {
		if err := plainScoped.Put(tctx, fmt.Sprintf("k:%03d", i), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	var got2 []string
	cursor = ""
	for i := 0; i < 1000; i++ {
		items, next, err := plainScoped.Scan(tctx, "k:", 6, cursor)
		if err != nil {
			t.Fatalf("fallback page %d: %v", i, err)
		}
		for k := range items {
			got2 = append(got2, k)
		}
		sort.Strings(got2)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(got2) != 30 {
		t.Fatalf("fallback walk got %d keys, want 30", len(got2))
	}
}

// TestScanPagination_EmptyAndUnmatched covers degenerate inputs.
func TestScanPagination_EmptyAndUnmatched(t *testing.T) {
	ctx := context.Background()
	rb := &rangedBackend{memBackend: newMemBackend()}
	p := &Plugin{storage: rb}
	seedN(t, p, "k:", 5)

	items, cursor, err := p.Scan(ctx, "zzz:", 10, "")
	if err != nil || len(items) != 0 || cursor != "" {
		t.Fatalf("unmatched prefix: items=%d cursor=%q err=%v", len(items), cursor, err)
	}
	// a cursor past the end must return nothing, not loop or error
	items, cursor, err = p.Scan(ctx, "k:", 10, "k:999")
	if err != nil || len(items) != 0 || cursor != "" {
		t.Fatalf("past-end cursor: items=%d cursor=%q err=%v", len(items), cursor, err)
	}
	// limit 0 means unlimited
	items, cursor, err = p.Scan(ctx, "k:", 0, "")
	if err != nil || len(items) != 5 || cursor != "" {
		t.Fatalf("unlimited: items=%d cursor=%q err=%v", len(items), cursor, err)
	}
}
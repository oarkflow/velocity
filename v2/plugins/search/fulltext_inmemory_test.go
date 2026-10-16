package search

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

type apiSearchHit = api.SearchHit

// asHits clones a hit slice so reflect.DeepEqual comparisons never alias.
func asHits(hits []api.SearchHit) []api.SearchHit {
	out := make([]api.SearchHit, len(hits))
	copy(out, hits)
	return out
}

// query shapes exercised across every path below: single term, two-term
// AND, negative term, quoted phrase, negative-without-required-term
// (AND semantics mean that matches NOTHING, never "all non-negative docs").
var ftQueryBattery = []string{
	"quick",
	"quick jumps",
	"jumps -cat",
	`"lazy dog"`,
	"-cat",
}

func ftTestDocs() []struct {
	key    string
	fields map[string]any
} {
	return []struct {
		key    string
		fields map[string]any
	}{
		{"doc1", map[string]any{"title": "The quick brown fox", "body": "jumps over the lazy dog"}},
		{"doc2", map[string]any{"title": "The quick blue hare", "body": "jumps over the sleepy cat"}},
		{"doc3", map[string]any{"title": "A slow green turtle", "body": "walks past the lazy dog"}},
		{"a/b", map[string]any{"title": "quick turtle jumps the fence"}},
	}
}

// TestFullTextInMemoryParityKVScan: with the same documents indexed
// through the same KV, the in-memory postings path must return exactly
// the hits the KV-scan fallback path returns — same keys, same scores —
// for every query shape (terms, AND, negative, phrase).
func TestFullTextInMemoryParityKVScan(t *testing.T) {
	ctx := context.Background()
	for _, query := range ftQueryBattery {
		var gotCache, gotScan []apiSearchHit
		for _, inMemory := range []bool{true, false} {
			kv := newMemKV()
			idx := newFullTextIndex(kv, inMemory)
			for _, d := range ftTestDocs() {
				if err := idx.Index(ctx, d.key, d.fields); err != nil {
					t.Fatalf("Index(%s): %v", d.key, err)
				}
				// Index twice: exercises Remove's stale-posting cleanup on re-index.
				if err := idx.Index(ctx, d.key, d.fields); err != nil {
					t.Fatalf("re-Index(%s): %v", d.key, err)
				}
			}
			hits, err := idx.Query(ctx, query, 10)
			if err != nil {
				t.Fatalf("Query(%q, inMemory=%v): %v", query, inMemory, err)
			}
			if inMemory {
				// second query on the warm cache must be identical to the first
				hits2, err := idx.Query(ctx, query, 10)
				if err != nil {
					t.Fatalf("Query(%q, inMemory warm): %v", query, err)
				}
				if !reflect.DeepEqual(asHits(hits), asHits(hits2)) {
					t.Fatalf("Query(%q): warm %v != cold %v", query, asHits(hits2), asHits(hits))
				}
			}
			if inMemory {
				gotCache = hits
			} else {
				gotScan = hits
			}
		}
		if !reflect.DeepEqual(asHits(gotCache), asHits(gotScan)) {
			t.Fatalf("Query(%q): in-memory %v != scan %v", query, asHits(gotCache), asHits(gotScan))
		}
	}
}

// TestFullTextWarmupAfterRestart proves the durable KV layer really is
// the source of truth: index through ONE index instance, drop it, and
// point a brand-new instance (no postings ever in RAM) at the same KV —
// its very first query triggers the warmup rebuild and returns the same
// results as the original.
func TestFullTextWarmupAfterRestart(t *testing.T) {
	ctx := context.Background()
	kv := newMemKV()
	first := newFullTextIndex(kv, true)
	if err := first.Index(ctx, "k-1", map[string]any{"title": "document number one about golang"}); err != nil {
		t.Fatal(err)
	}
	if err := first.Index(ctx, "k-2", map[string]any{"title": "nothing relevant here"}); err != nil {
		t.Fatal(err)
	}
	firstHits, err := first.Query(ctx, "golang", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstHits) != 1 || firstHits[0].Key != "k-1" {
		t.Fatalf("sanity: %+v", firstHits)
	}

	// "restart": a new index over the same, already-populated KV.
	restarted := newFullTextIndex(kv, true)
	afterHits, err := restarted.Query(ctx, "golang", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(asHits(afterHits), asHits(firstHits)) {
		t.Fatalf("after-restart warmup %v, want same as %v", asHits(afterHits), asHits(firstHits))
	}

	// Remove through the restarted instance keeps both KV and RAM coherent.
	if err := restarted.Remove(ctx, "k-1"); err != nil {
		t.Fatal(err)
	}
	hits, err := restarted.Query(ctx, "golang", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("after remove want 0 hits, got %v", asHits(hits))
	}
}

// TestFullTextInMemoryConcurrency hammers queries against concurrent
// re-indexing with the race detector: interleaved cacheAdd/cacheRemove
// (copy-on-write term maps) must never trip a data race or crash an
// intersect in progress.
func TestFullTextInMemoryConcurrency(t *testing.T) {
	ctx := context.Background()
	for _, inMemory := range []bool{true, false} {
		kv := newMemKV()
		idx := newFullTextIndex(kv, inMemory)
		for i := 0; i < 50; i++ {
			fields := map[string]any{"title": fmt.Sprintf("quick word%d tail%d", i%4, i)}
			if err := idx.Index(ctx, fmt.Sprintf("doc-%d", i), fields); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 50; i++ {
					if _, err := idx.Query(ctx, "quick word0", 10); err != nil {
						t.Errorf("Query: %v", err)
						return
					}
				}
			}()
		}
		for i := 0; i < 25; i++ {
			fields := map[string]any{"title": fmt.Sprintf("updated quick word%d", i%4)}
			if err := idx.Index(ctx, fmt.Sprintf("doc-%d", i), fields); err != nil {
				t.Fatal(err)
			}
			if err := idx.Remove(ctx, fmt.Sprintf("doc-%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		wg.Wait()
	}
}

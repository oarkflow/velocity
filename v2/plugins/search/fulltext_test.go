package search

import (
	"context"
	"testing"
)

func TestFullTextIndexQueryRoundTrip(t *testing.T) {
	ctx := context.Background()
	kv := newMemKV()
	idx := newFullTextIndex(kv)

	docs := map[string]map[string]any{
		"doc1": {"title": "The quick brown fox", "body": "jumps over the lazy dog"},
		"doc2": {"title": "The quick blue hare", "body": "jumps over the sleepy cat"},
		"doc3": {"title": "A slow green turtle", "body": "walks past the lazy dog"},
	}
	for key, fields := range docs {
		if err := idx.Index(ctx, key, fields); err != nil {
			t.Fatalf("Index(%s): %v", key, err)
		}
	}

	// Plain AND term match: "quick" appears in doc1 and doc2.
	hits, err := idx.Query(ctx, "quick", 10)
	if err != nil {
		t.Fatalf("Query(quick): %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("Query(quick) = %d hits, want 2: %+v", len(hits), hits)
	}

	// Two-term AND: "quick jumps" should match doc1 and doc2, not doc3.
	hits, err = idx.Query(ctx, "quick jumps", 10)
	if err != nil {
		t.Fatalf("Query(quick jumps): %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("Query(quick jumps) = %d hits, want 2: %+v", len(hits), hits)
	}

	// Negative term: "lazy dog" matches doc1 and doc3, "-cat" excludes
	// nothing new here but proves the negative path works by excluding
	// doc2 from a broader "jumps" query it would otherwise match.
	hits, err = idx.Query(ctx, "jumps -cat", 10)
	if err != nil {
		t.Fatalf("Query(jumps -cat): %v", err)
	}
	for _, h := range hits {
		if h.Key == "doc2" {
			t.Fatalf("Query(jumps -cat) should have excluded doc2 (contains 'cat'), got hits=%+v", hits)
		}
	}
	if len(hits) != 1 || hits[0].Key != "doc1" {
		t.Fatalf("Query(jumps -cat) = %+v, want exactly [doc1]", hits)
	}

	// Phrase match: quoted phrase must appear verbatim (substring of the
	// lowercased concatenated text).
	hits, err = idx.Query(ctx, `"lazy dog"`, 10)
	if err != nil {
		t.Fatalf("Query(\"lazy dog\"): %v", err)
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Key] = true
	}
	if !got["doc1"] || !got["doc3"] || got["doc2"] {
		t.Fatalf(`Query("lazy dog") = %+v, want exactly [doc1, doc3]`, hits)
	}

	// Remove takes a doc out of every posting list.
	if err := idx.Remove(ctx, "doc1"); err != nil {
		t.Fatalf("Remove(doc1): %v", err)
	}
	hits, err = idx.Query(ctx, "quick", 10)
	if err != nil {
		t.Fatalf("Query(quick) after remove: %v", err)
	}
	if len(hits) != 1 || hits[0].Key != "doc2" {
		t.Fatalf("Query(quick) after removing doc1 = %+v, want exactly [doc2]", hits)
	}
}

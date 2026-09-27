package search

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func TestExtractEntities_FindsKnownPatterns(t *testing.T) {
	e := newEntityExtraction(0)
	text := "Contact Dr. John Smith at john.smith@example.com or visit https://example.com. " +
		"Acme Technologies Inc. signed on 2024-03-15 for $12,500.00."

	got, err := e.ExtractEntities(context.Background(), text)
	if err != nil {
		t.Fatalf("ExtractEntities: %v", err)
	}

	byType := map[string][]string{}
	for _, ent := range got {
		if text[ent.Start:ent.End] != ent.Text {
			t.Errorf("span mismatch for %q: text[%d:%d]=%q", ent.Text, ent.Start, ent.End, text[ent.Start:ent.End])
		}
		byType[ent.Type] = append(byType[ent.Type], ent.Text)
	}

	wantTypes := []string{"EMAIL", "URL", "DATE", "MONEY", "PERSON", "ORG"}
	for _, wt := range wantTypes {
		if len(byType[wt]) == 0 {
			t.Errorf("expected at least one %s entity, found none (got types: %v)", wt, keysOf(byType))
		}
	}

	if got0 := byType["EMAIL"]; len(got0) != 1 || got0[0] != "john.smith@example.com" {
		t.Errorf("EMAIL = %v, want [john.smith@example.com]", got0)
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestResolveEntities_MergesSimilarNotDistinct(t *testing.T) {
	e := newEntityExtraction(0.85)

	// "acme corp" and "acme corp." should cluster (Jaro-Winkler similarity
	// above threshold for a one-character difference); "widget inc" is
	// clearly distinct and must NOT be merged into that cluster.
	ids := []string{"acme corp", "acme corp.", "widget inc"}

	res, err := e.ResolveEntities(context.Background(), ids)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}

	var acmeCluster, widgetCluster *struct {
		canonical string
		merged    []string
	}
	for _, r := range res {
		found := struct {
			canonical string
			merged    []string
		}{r.CanonicalID, r.MergedIDs}
		for _, id := range r.MergedIDs {
			if id == "acme corp" || id == "acme corp." {
				acmeCluster = &found
			}
			if id == "widget inc" {
				widgetCluster = &found
			}
		}
	}

	if acmeCluster == nil {
		t.Fatal("expected a cluster containing the acme corp variants")
	}
	if len(acmeCluster.merged) != 2 {
		t.Errorf("acme cluster = %v, want both acme variants merged together", acmeCluster.merged)
	}
	if widgetCluster == nil || len(widgetCluster.merged) != 1 {
		t.Errorf("widget inc must remain its own cluster, got %+v", widgetCluster)
	}
}

func TestChunkText_RespectsWordWindowAndHandlesShortText(t *testing.T) {
	e := newEntityExtraction(0)

	short := "just a few words here"
	chunks, err := e.ChunkText(context.Background(), short, 256)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(chunks) != 1 || chunks[0] != short {
		t.Errorf("short text should yield exactly one unmodified chunk, got %v", chunks)
	}

	// Build text with 300 distinct words; maxWords=100 with a 64-word
	// overlap (v1's default) should produce multiple overlapping chunks,
	// none exceeding 100 words.
	words := make([]string, 300)
	for i := range words {
		words[i] = "w" + strconv.Itoa(i)
	}
	long := strings.Join(words, " ")

	longChunks, err := e.ChunkText(context.Background(), long, 100)
	if err != nil {
		t.Fatalf("ChunkText: %v", err)
	}
	if len(longChunks) < 2 {
		t.Fatalf("expected multiple chunks for 300 words at maxWords=100, got %d", len(longChunks))
	}
	for i, c := range longChunks {
		n := len(strings.Fields(c))
		if n > 100 {
			t.Errorf("chunk %d has %d words, want <= 100", i, n)
		}
	}
}

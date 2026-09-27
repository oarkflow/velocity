package redisdata

import (
	"context"
	"math"
	"sort"
	"testing"
)

func TestSortedFloatBytes_OrderMatchesValueOrder(t *testing.T) {
	values := []float64{
		math.Inf(-1), -1000.5, -1, -0.5, -0.0001, 0, 0.0001, 0.5, 1, 1000.5, math.Inf(1),
	}
	// Compute expected order (values is already ascending) and compare
	// against sorting the encoded byte forms.
	type pair struct {
		f float64
		b []byte
	}
	pairs := make([]pair, len(values))
	for i, f := range values {
		pairs[i] = pair{f: f, b: sortableFloatBytes(f)}
	}
	sorted := make([]pair, len(pairs))
	copy(sorted, pairs)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i].b) < string(sorted[j].b)
	})
	for i := range sorted {
		if sorted[i].f != values[i] {
			t.Fatalf("byte-order sort mismatch at index %d: got %v, want %v (full: %v)", i, sorted[i].f, values[i], values)
		}
	}
}

func TestZSet_AddRangeScoreRemCard(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	entries := []struct {
		member string
		score  float64
	}{
		{"c", 3.5}, {"a", -1.2}, {"b", 0}, {"d", 100},
	}
	for _, e := range entries {
		if err := p.ZAdd(ctx, "z", e.score, []byte(e.member)); err != nil {
			t.Fatal(err)
		}
	}

	card, err := p.ZCard(ctx, "z")
	if err != nil || card != 4 {
		t.Fatalf("ZCard: card=%d err=%v", card, err)
	}

	got, err := p.ZRange(ctx, "z", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "a", "b", "c", "d")

	score, ok, err := p.ZScore(ctx, "z", []byte("c"))
	if err != nil || !ok || score != 3.5 {
		t.Fatalf("ZScore(c): score=%v ok=%v err=%v", score, ok, err)
	}

	if err := p.ZRem(ctx, "z", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := p.ZScore(ctx, "z", []byte("b")); err != nil || ok {
		t.Fatalf("ZScore(b) after ZRem: ok=%v err=%v", ok, err)
	}
	got, err = p.ZRange(ctx, "z", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "a", "c", "d")
}

func TestZSet_ReAddUpdatesScoreWithoutStaleEntry(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.ZAdd(ctx, "z", 10, []byte("m")); err != nil {
		t.Fatal(err)
	}
	if err := p.ZAdd(ctx, "z", 5, []byte("m")); err != nil {
		t.Fatal(err)
	}
	if err := p.ZAdd(ctx, "z", 20, []byte("other")); err != nil {
		t.Fatal(err)
	}

	// Only one entry for "m" should exist, at its NEW score (5), not the
	// old one (10) — ZRange must show it exactly once, in the right
	// position.
	got, err := p.ZRange(ctx, "z", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	assertByteSlices(t, got, "m", "other")

	card, err := p.ZCard(ctx, "z")
	if err != nil || card != 2 {
		t.Fatalf("ZCard: card=%d err=%v (stale entry would inflate this)", card, err)
	}

	score, ok, err := p.ZScore(ctx, "z", []byte("m"))
	if err != nil || !ok || score != 5 {
		t.Fatalf("ZScore(m): score=%v ok=%v err=%v", score, ok, err)
	}
}

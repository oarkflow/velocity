package velocity

import (
	"math"
	"testing"
)

func TestCosineSimilarity(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{1, 0, 0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim-1.0) > 1e-6 {
		t.Fatalf("identical vectors should have similarity 1.0, got %f", sim)
	}

	c := []float32{0, 1, 0}
	sim2 := cosineSimilarity(a, c)
	if math.Abs(sim2) > 1e-6 {
		t.Fatalf("orthogonal vectors should have similarity 0.0, got %f", sim2)
	}

	d := []float32{-1, 0, 0}
	sim3 := cosineSimilarity(a, d)
	if math.Abs(sim3+1.0) > 1e-6 {
		t.Fatalf("opposite vectors should have similarity -1.0, got %f", sim3)
	}
}

func TestEncodeDecodeFloat32s(t *testing.T) {
	orig := []float32{1.5, -2.3, 0, 100.001}
	encoded := encodeFloat32s(orig)
	decoded := decodeFloat32s(encoded)

	if len(decoded) != len(orig) {
		t.Fatalf("length mismatch: %d vs %d", len(decoded), len(orig))
	}
	for i := range orig {
		if orig[i] != decoded[i] {
			t.Fatalf("value mismatch at %d: %f vs %f", i, orig[i], decoded[i])
		}
	}
}

func TestHNSWIndex_InsertAndSearch(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	idx, err := NewHNSWIndex(db, HNSWConfig{
		M:              8,
		EfConstruction: 100,
		EfSearch:       50,
		Dimension:      3,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Insert some vectors
	vectors := map[string][]float32{
		"v1": {1, 0, 0},
		"v2": {0.9, 0.1, 0},
		"v3": {0, 1, 0},
		"v4": {0, 0, 1},
		"v5": {0.8, 0.2, 0},
	}

	for id, vec := range vectors {
		if err := idx.Insert(id, vec); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	if idx.NodeCount() != 5 {
		t.Fatalf("expected 5 nodes, got %d", idx.NodeCount())
	}

	// Search for vector close to [1, 0, 0]
	results, err := idx.Search([]float32{1, 0, 0}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	// v1 should be the closest
	if results[0].ChunkID != "v1" {
		t.Fatalf("expected v1 as closest, got %s", results[0].ChunkID)
	}
}

func TestHNSWIndex_Delete(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	idx, err := NewHNSWIndex(db, HNSWConfig{
		M: 8, EfConstruction: 50, EfSearch: 30, Dimension: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	idx.Insert("a", []float32{1, 0})
	idx.Insert("b", []float32{0, 1})

	if idx.NodeCount() != 2 {
		t.Fatalf("expected 2 nodes, got %d", idx.NodeCount())
	}

	idx.Delete("a")
	if idx.NodeCount() != 1 {
		t.Fatalf("expected 1 node after delete, got %d", idx.NodeCount())
	}
}

func TestHNSWIndex_DimensionMismatch(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	idx, err := NewHNSWIndex(db, HNSWConfig{Dimension: 3})
	if err != nil {
		t.Fatal(err)
	}

	err = idx.Insert("v1", []float32{1, 0})
	if err == nil {
		t.Fatal("expected error for dimension mismatch")
	}
}

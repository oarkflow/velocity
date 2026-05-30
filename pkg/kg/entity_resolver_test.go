package velocity

import (
	"math"
	"testing"
)

func TestJaroWinkler_Identical(t *testing.T) {
	sim := jaroWinkler("hello", "hello")
	if sim != 1.0 {
		t.Fatalf("expected 1.0, got %f", sim)
	}
}

func TestJaroWinkler_Empty(t *testing.T) {
	sim := jaroWinkler("", "hello")
	if sim != 0.0 {
		t.Fatalf("expected 0.0, got %f", sim)
	}
}

func TestJaroWinkler_Similar(t *testing.T) {
	sim := jaroWinkler("martha", "marhta")
	if sim < 0.9 {
		t.Fatalf("expected high similarity for martha/marhta, got %f", sim)
	}
}

func TestJaroWinkler_Different(t *testing.T) {
	sim := jaroWinkler("abc", "xyz")
	if sim > 0.5 {
		t.Fatalf("expected low similarity for abc/xyz, got %f", sim)
	}
}

func TestEntityResolver_Dedup(t *testing.T) {
	resolver := NewEntityResolver(0.85)

	entities := []KGEntity{
		{Surface: "John Smith", Type: "PERSON", Confidence: 0.8},
		{Surface: "John Smith", Type: "PERSON", Confidence: 0.7},
		{Surface: "john smith", Type: "PERSON", Confidence: 0.6},
		{Surface: "Alice Jones", Type: "PERSON", Confidence: 0.8},
	}

	resolved := resolver.Resolve(entities)
	if len(resolved) != 4 {
		t.Fatalf("expected 4 entities (unchanged count), got %d", len(resolved))
	}

	// All "John Smith" variants should have the same canonical
	canonicals := make(map[string]int)
	for _, e := range resolved {
		if e.Type == "PERSON" {
			canonicals[e.Canonical]++
		}
	}
	// "John Smith" cluster should have 3 entries and "Alice Jones" should have 1
	if len(canonicals) != 2 {
		t.Fatalf("expected 2 unique canonicals, got %d: %v", len(canonicals), canonicals)
	}
}

func TestEntityResolver_DifferentTypes(t *testing.T) {
	resolver := NewEntityResolver(0.85)

	entities := []KGEntity{
		{Surface: "Apple", Type: "ORG", Confidence: 0.8},
		{Surface: "Apple", Type: "FOOD", Confidence: 0.7},
	}

	resolved := resolver.Resolve(entities)
	// Same surface but different types should NOT be merged
	orgCount := 0
	foodCount := 0
	for _, e := range resolved {
		if e.Type == "ORG" {
			orgCount++
		}
		if e.Type == "FOOD" {
			foodCount++
		}
	}
	if orgCount != 1 || foodCount != 1 {
		t.Fatalf("expected 1 ORG and 1 FOOD, got %d and %d", orgCount, foodCount)
	}
}

func TestEntityResolver_Single(t *testing.T) {
	resolver := NewEntityResolver(0.85)
	entities := []KGEntity{
		{Surface: "Test", Type: "ORG", Confidence: 0.9},
	}
	resolved := resolver.Resolve(entities)
	if len(resolved) != 1 {
		t.Fatalf("expected 1, got %d", len(resolved))
	}
}

func TestJaroSimilarity_Symmetric(t *testing.T) {
	s1 := jaroSimilarity("hello", "hallo")
	s2 := jaroSimilarity("hallo", "hello")
	if math.Abs(s1-s2) > 1e-10 {
		t.Fatalf("jaro should be symmetric: %f vs %f", s1, s2)
	}
}

package benchmarks

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkFullTextIndex(b *testing.B) {
	ft, _, cleanup := bootSearch(b)
	defer cleanup()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("doc-%d", i)
		fields := map[string]any{"title": fmt.Sprintf("document number %d about golang and databases", i)}
		if err := ft.Index(ctx, key, fields); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFullTextQuery(b *testing.B) {
	ft, _, cleanup := bootSearch(b)
	defer cleanup()
	ctx := context.Background()
	const n = 2000
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("doc-%d", i)
		fields := map[string]any{"title": fmt.Sprintf("document number %d about golang and databases", i)}
		if err := ft.Index(ctx, key, fields); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ft.Query(ctx, "golang databases", 10); err != nil {
			b.Fatal(err)
		}
	}
}

func randVec(r *rand.Rand, dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = r.Float32()
	}
	return v
}

func benchVectorUpsert(b *testing.B, dim int) {
	_, vec, cleanup := bootSearch(b)
	defer cleanup()
	ctx := context.Background()
	r := rand.New(rand.NewSource(1))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("v-%d", i)
		if err := vec.Upsert(ctx, id, randVec(r, dim), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVectorUpsert_Dim12(b *testing.B) { benchVectorUpsert(b, 12) }

func benchVectorSearch(b *testing.B, n, dim int) {
	_, vec, cleanup := bootSearch(b)
	defer cleanup()
	ctx := context.Background()
	r := rand.New(rand.NewSource(1))
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("v-%d", i)
		if err := vec.Upsert(ctx, id, randVec(r, dim), nil); err != nil {
			b.Fatal(err)
		}
	}
	query := randVec(r, dim)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := vec.Search(ctx, query, 10); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVectorSearch_1000(b *testing.B)  { benchVectorSearch(b, 1000, 12) }
func BenchmarkVectorSearch_10000(b *testing.B) { benchVectorSearch(b, 10000, 12) }

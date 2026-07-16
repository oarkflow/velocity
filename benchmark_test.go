package velocity

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

func benchConfig(path string) Config {
	return Config{
		Path:              path,
		DisableEncryption: true,
		DisableWAL:        true,
		DisableFsync:      true,
	}
}

func benchConfigWithSearch(path string, schemas map[string]*SearchSchema) Config {
	return Config{
		Path:                    path,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		SearchSchemas:           schemas,
		SearchIndexEnabled:      true,
		DisableIndexPersistence: true,
	}
}

func openBenchDB(b *testing.B, path string) *DB {
	b.Helper()
	db, err := NewWithConfig(benchConfig(path))
	if err != nil {
		b.Fatal(err)
	}
	return db
}

func openBenchDBWithSearch(b *testing.B, path string, schemas map[string]*SearchSchema) *DB {
	b.Helper()
	db, err := NewWithConfig(benchConfigWithSearch(path, schemas))
	if err != nil {
		b.Fatal(err)
	}
	return db
}

func benchSearchSchema() map[string]*SearchSchema {
	return map[string]*SearchSchema{
		"user": {
			Fields: []SearchSchemaField{
				{Name: "id", HashSearch: true, ValueIndex: true},
				{Name: "name", Searchable: true},
				{Name: "email", Searchable: true, HashSearch: true},
				{Name: "age", HashSearch: true, ValueIndex: true},
				{Name: "city", HashSearch: true, ValueIndex: true},
				{Name: "bio", Searchable: true},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// KV Operations
// ---------------------------------------------------------------------------

func BenchmarkPut(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_put")
	db := openBenchDB(b, path)
	defer db.Close()

	data := []byte(`{"id":1,"name":"test","value":true}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_get")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf("value_%d", i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k:%d", i%5000)
		if _, err := db.Get([]byte(key)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetCold(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_get_cold")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf("value_%d", i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k:%d", rand.Intn(10000))
		if _, err := db.Get([]byte(key)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHas(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_has")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf("value_%d", i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Has([]byte(fmt.Sprintf("k:%d", i%5000)))
	}
}

func BenchmarkDelete(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_delete")
	db := openBenchDB(b, path)
	defer db.Close()

	// Pre-populate
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf("value_%d", i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Delete([]byte(key)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPutWithTTL(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_put_ttl")
	db := openBenchDB(b, path)
	defer db.Close()

	data := []byte(`{"id":1,"name":"ephemeral"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("ephemeral:%d", i)
		if err := db.PutWithTTL([]byte(key), data, 5*time.Minute); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIncr(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_incr")
	db := openBenchDB(b, path)
	defer db.Close()

	key := []byte("counter:1")
	if err := db.Put(key, []byte("0")); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Incr(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecr(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_decr")
	db := openBenchDB(b, path)
	defer db.Close()

	key := []byte("counter:1")
	if err := db.Put(key, []byte("100000")); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Decr(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTTL(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_ttl")
	db := openBenchDB(b, path)
	defer db.Close()

	key := []byte("ttl:test")
	if err := db.PutWithTTL(key, []byte("value"), 10*time.Minute); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.TTL(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchWrite(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_batch")
	db := openBenchDB(b, path)
	defer db.Close()

	payload := []byte(`{"id":1,"name":"batch"}`)
	sizes := []int{10, 100, 1000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bw := db.NewBatchWriter(size)
				for j := 0; j < size; j++ {
					key := fmt.Sprintf("batch:%d:%d", i, j)
					if err := bw.Put([]byte(key), payload); err != nil {
						b.Fatal(err)
					}
				}
				if err := bw.Flush(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Listing / Scan Operations
// ---------------------------------------------------------------------------

func BenchmarkScan(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_scan")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("user:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf(`{"id":%d,"name":"user_%d"}`, i, i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		if err := db.Scan([]byte("user:"), func(key, value []byte) bool {
			count++
			return count < 100
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeys(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_keys")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("user:%d", i)
		if err := db.Put([]byte(key), []byte(`{"name":"test"}`)); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("ExactMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := db.Keys("user:5000"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("PrefixWildcard", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := db.Keys("user:*"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("AllKeys", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := db.Keys("*"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkKeysPage(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_keyspage")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("k:%08d", i)
		if err := db.Put([]byte(key), []byte(`{"val":1}`)); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.KeysPage(0, 50)
	}
}

func BenchmarkScanFull(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_scanfull")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("item:%d", i)
		if err := db.Put([]byte(key), []byte(`{"x":1}`)); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := db.Scan([]byte("item:"), func(key, value []byte) bool {
			return true
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Search / Lucene Replacement Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPutIndexed(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_putindexed")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)
	defer db.Close()

	schema := schemas["user"]
	payload := []byte(`{"id":1,"name":"John Doe","email":"john@example.com","age":30,"city":"New York","bio":"Software engineer"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("user:%d", i)
		if err := db.PutIndexed([]byte(key), payload, schema); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSearchByFilter(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_search_filter")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)
	defer db.Close()

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("user:%d", i)
		payload, _ := json.Marshal(map[string]any{
			"id":    i,
			"name":  fmt.Sprintf("user_%d", i),
			"email": fmt.Sprintf("user%d@example.com", i),
			"age":   20 + (i % 50),
			"city":  []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[i%5],
			"bio":   fmt.Sprintf("bio number %d", i),
		})
		if err := db.PutIndexed([]byte(key), payload, schemas["user"]); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("Equality", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix: "user",
			Filters: []SearchFilter{
				{Field: "city", Op: "=", Value: "Tokyo"},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Range", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix: "user",
			Filters: []SearchFilter{
				{Field: "age", Op: ">=", Value: 40},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("MultipleFilters", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix: "user",
			Filters: []SearchFilter{
				{Field: "city", Op: "=", Value: "London"},
				{Field: "age", Op: ">=", Value: 30},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSearchFullText(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_search_ft")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)
	defer db.Close()

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("user:%d", i)
		payload, _ := json.Marshal(map[string]any{
			"id":    i,
			"name":  []string{"Alice", "Bob", "Charlie", "Diana", "Eve"}[i%5],
			"email": fmt.Sprintf("user%d@example.com", i),
			"age":   20 + (i % 50),
			"city":  []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[i%5],
			"bio":   fmt.Sprintf("Software engineer with %d years of experience in Go and distributed systems", i%20),
		})
		if err := db.PutIndexed([]byte(key), payload, schemas["user"]); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("SingleTerm", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix:   "user",
			FullText: "engineer",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Phrase", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix:    "user",
			FullText:  "distributed systems",
			MatchMode: "phrase",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Combined", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix:   "user",
			FullText: "Go engineer",
			Filters: []SearchFilter{
				{Field: "city", Op: "=", Value: "Berlin"},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.Search(q); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSearchCount(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_searchcount")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)
	defer db.Close()

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("user:%d", i)
		payload, _ := json.Marshal(map[string]any{
			"id":    i,
			"name":  fmt.Sprintf("user_%d", i),
			"email": fmt.Sprintf("user%d@example.com", i),
			"age":   20 + (i % 50),
			"city":  []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[i%5],
		})
		if err := db.PutIndexed([]byte(key), payload, schemas["user"]); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("FilterCount", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix: "user",
			Filters: []SearchFilter{
				{Field: "age", Op: ">=", Value: 40},
			},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.SearchCount(q); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FullTextCount", func(b *testing.B) {
		b.ReportAllocs()
		q := SearchQuery{
			Prefix:   "user",
			FullText: "user",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := db.SearchCount(q); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRebuildIndex(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_reindex")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("user:%d", i)
		payload, _ := json.Marshal(map[string]any{
			"id":    i,
			"name":  fmt.Sprintf("user_%d", i),
			"email": fmt.Sprintf("user%d@example.com", i),
			"age":   20 + (i % 50),
			"city":  []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[i%5],
			"bio":   "some text for indexing",
		})
		if err := db.Put([]byte(key), payload); err != nil {
			b.Fatal(err)
		}
	}
	db.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db2 := openBenchDBWithSearch(b, filepath.Join(b.TempDir(), fmt.Sprintf("bench_reindex_run_%d", i)), schemas)
		for j := 0; j < 5000; j++ {
			key := fmt.Sprintf("user:%d", j)
			payload, _ := json.Marshal(map[string]any{
				"id":    j,
				"name":  fmt.Sprintf("user_%d", j),
				"email": fmt.Sprintf("user%d@example.com", j),
				"age":   20 + (j % 50),
				"city":  []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[j%5],
				"bio":   "some text for indexing",
			})
			if err := db2.Put([]byte(key), payload); err != nil {
				b.Fatal(err)
			}
		}
		if err := db2.RebuildIndex("user", schemas["user"], &RebuildOptions{
			BatchSize: 2000,
			NoWAL:     true,
		}); err != nil {
			b.Fatal(err)
		}
		db2.Close()
	}
}

// ---------------------------------------------------------------------------
// Concurrent Operations
// ---------------------------------------------------------------------------

func BenchmarkConcurrentPut(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_concurrent_put")
	db := openBenchDB(b, path)
	defer db.Close()

	payload := []byte(`{"x":1}`)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("concurrent:%d", i)
			_ = db.Put([]byte(key), payload)
			i++
		}
	})
}

func BenchmarkConcurrentGet(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_concurrent_get")
	db := openBenchDB(b, path)
	defer db.Close()

	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("k:%d", i)
		if err := db.Put([]byte(key), []byte(fmt.Sprintf("value_%d", i))); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			key := fmt.Sprintf("k:%d", rnd.Intn(10000))
			_, _ = db.Get([]byte(key))
		}
	})
}

func BenchmarkConcurrentPutGet(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_concurrent_putget")
	db := openBenchDB(b, path)
	defer db.Close()

	payload := []byte(`{"x":1}`)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("k:%d", i%10000)
			if i%2 == 0 {
				_ = db.Put([]byte(key), payload)
			} else {
				_, _ = db.Get([]byte(key))
			}
			i++
		}
	})
}

// ---------------------------------------------------------------------------
// Mixed workload simulating real-world usage
// ---------------------------------------------------------------------------

func BenchmarkMixedWorkload(b *testing.B) {
	b.ReportAllocs()
	path := filepath.Join(b.TempDir(), "bench_mixed")
	schemas := benchSearchSchema()
	db := openBenchDBWithSearch(b, path, schemas)
	defer db.Close()

	// Pre-seed
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("user:%d", i)
		payload, _ := json.Marshal(map[string]any{
			"id":   i,
			"name": fmt.Sprintf("user_%d", i),
			"age":  20 + (i % 50),
			"city": []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[i%5],
			"bio":  "experienced Go developer",
		})
		if err := db.PutIndexed([]byte(key), payload, schemas["user"]); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			switch rnd.Intn(5) {
			case 0:
				id := rnd.Intn(1000)
				key := fmt.Sprintf("user:%d", id)
				_, _ = db.Get([]byte(key))
			case 1:
				q := SearchQuery{
					Prefix: "user",
					Filters: []SearchFilter{
						{Field: "city", Op: "=", Value: []string{"New York", "London", "Tokyo", "Paris", "Berlin"}[rnd.Intn(5)]},
					},
				}
				_, _ = db.Search(q)
			case 2:
				q := SearchQuery{
					Prefix:   "user",
					FullText: "Go developer",
				}
				_, _ = db.Search(q)
			case 3:
				id := 1000 + rnd.Intn(1000)
				key := fmt.Sprintf("user:%d", id)
				payload, _ := json.Marshal(map[string]any{
					"id":   id,
					"name": fmt.Sprintf("new_user_%d", id),
					"age":  20 + rnd.Intn(50),
					"city": "Berlin",
					"bio":  "new Go developer",
				})
				_ = db.PutIndexed([]byte(key), payload, schemas["user"])
			case 4:
				key := fmt.Sprintf("user:%d", rnd.Intn(100))
				_ = db.Delete([]byte(key))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Benchmark with realistic payload sizes
// ---------------------------------------------------------------------------

func BenchmarkPutPayloadSizes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4 * 1024},
		{"16KB", 16 * 1024},
		{"64KB", 64 * 1024},
	}

	for _, s := range sizes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			path := filepath.Join(b.TempDir(), "bench_payload_"+s.name)
			db := openBenchDB(b, path)
			defer db.Close()

			data := make([]byte, s.size)
			rand.Read(data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("k:%d", i)
				if err := db.Put([]byte(key), data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGetPayloadSizes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4 * 1024},
		{"16KB", 16 * 1024},
		{"64KB", 64 * 1024},
	}

	for _, s := range sizes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			path := filepath.Join(b.TempDir(), "bench_get_"+s.name)
			db := openBenchDB(b, path)
			defer db.Close()

			data := make([]byte, s.size)
			rand.Read(data)

			for i := 0; i < 1000; i++ {
				key := fmt.Sprintf("k:%d", i)
				if err := db.Put([]byte(key), data); err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("k:%d", i%1000)
				if _, err := db.Get([]byte(key)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

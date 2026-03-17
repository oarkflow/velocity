//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	path := "./search_index_demo_db"
	if v := os.Getenv("VELOCITY_DEMO_DB"); v != "" {
		path = v
	}

	records := 1_000_000
	if v := os.Getenv("VELOCITY_RECORDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			records = n
		}
	}

	// Always start with a clean database for consistent results
	_ = os.RemoveAll(path)

	db, err := velocity.NewWithConfig(velocity.Config{Path: path})
	if err != nil {
		panic(err)
	}
	defer db.Close()

	schema := &velocity.SearchSchema{Fields: []velocity.SearchSchemaField{
		{Name: "email", Searchable: false, HashSearch: true},
		{Name: "age", Searchable: true, HashSearch: false},
		{Name: "location", Searchable: true, HashSearch: true},
		{Name: "name", Searchable: true, HashSearch: false},
	}}

	db.SetSearchSchemaForPrefix("users", schema)
	// Fast ingest: disable online indexing, rebuild once at the end
	db.EnableSearchIndex(false)

	rand.Seed(42)
	locations := []string{"london", "paris", "berlin", "madrid", "rome", "oslo", "dublin", "helsinki"}
	firstNames := []string{"john", "jane", "alex", "emma", "mike", "sara", "liam", "olivia"}

	// Count expected matches for verification
	expectedMatches := 0
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < records; i++ {
		name := firstNames[rng.Intn(len(firstNames))]
		loc := locations[rng.Intn(len(locations))]
		age := 18 + rng.Intn(60)
		if name == "john" && loc == "london" && age > 30 {
			expectedMatches++
		}
	}
	expectedMatches++ // +1 for forced record

	// Reset for actual data generation
	rng = rand.New(rand.NewSource(42))

	start := time.Now()
	bw := db.NewBatchWriter(5000)
	defer bw.Flush()
	lastLog := time.Now()
	for i := 0; i < records; i++ {
		name := firstNames[rng.Intn(len(firstNames))]
		loc := locations[rng.Intn(len(locations))]
		age := 18 + rng.Intn(60)
		email := fmt.Sprintf("%s%06d@example.com", name, i)
		value := fmt.Sprintf(`{"email":"%s","age":%d,"location":"%s","name":"%s"}`, email, age, loc, name)
		key := fmt.Sprintf("users:%d", i)
		if err := bw.Put([]byte(key), []byte(value)); err != nil {
			panic(err)
		}
		if i > 0 && i%100000 == 0 {
			_ = bw.Flush()
		}
		if time.Since(lastLog) > 2*time.Second {
			fmt.Printf("Inserted %d/%d...\n", i, records)
			lastLog = time.Now()
		}
	}
	// Insert a guaranteed match for deterministic search results
	forced := `{"email":"john.test@example.com","age":35,"location":"london","name":"john"}`
	if err := bw.Put([]byte("users:forced"), []byte(forced)); err != nil {
		panic(err)
	}
	_ = bw.Flush()
	fmt.Printf("Inserted %d records in %s\n", records, time.Since(start))

	idxStart := time.Now()
	if err := db.RebuildIndex("users", schema, nil); err != nil {
		panic(err)
	}
	fmt.Printf("Index rebuilt in %s\n", time.Since(idxStart))

	// Enable online indexing after rebuild (optional)
	db.EnableSearchIndex(true)

	// Example query
	q := velocity.SearchQuery{
		Prefix:   "users",
		FullText: "john",
		Filters: []velocity.SearchFilter{
			{Field: "location", Op: "==", Value: "london", HashOnly: true},
			{Field: "age", Op: ">", Value: 30},
		},
		Limit: 20,
	}

	qStart := time.Now()
	results, err := db.Search(q)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Search returned %d results in %s (expected %d)\n", len(results), time.Since(qStart), min(expectedMatches, q.Limit))
	if len(results) != min(expectedMatches, q.Limit) {
		fmt.Printf("WARNING: Result count mismatch! Expected %d, got %d\n", min(expectedMatches, q.Limit), len(results))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

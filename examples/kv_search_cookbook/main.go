package main

import (
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    dir,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableIndexPersistence: true,
		SearchIndexEnabled:      true,
		SQLQueryCacheDisabled:   true,
	})
	check(err)
	defer db.Close()

	defaultSchema := &velocity.SearchSchema{Fields: []velocity.SearchSchemaField{
		{Name: "$value", Searchable: true},
	}}
	userSchema := &velocity.SearchSchema{Fields: []velocity.SearchSchemaField{
		{Name: "name", Searchable: true},
		{Name: "email", HashSearch: true},
		{Name: "region", Searchable: true, HashSearch: true},
		{Name: "spend", ValueIndex: true},
	}}
	db.SetSearchSchema(defaultSchema)
	db.SetSearchSchemaForPrefix("users", userSchema)

	check(db.Put([]byte("note:1"), []byte("Velocity search supports phrase and boolean matching.")))
	check(db.Put([]byte("users:1"), []byte(`{"name":"Ada Lovelace","email":"ada@example.test","region":"EU","spend":125}`)))
	check(db.Put([]byte("users:2"), []byte(`{"name":"Grace Hopper","email":"grace@example.test","region":"US","spend":300}`)))
	check(db.PutWithTTL([]byte("session:tmp"), []byte("short lived"), 50*time.Millisecond))

	counter, err := db.Incr([]byte("counter"), 2)
	check(err)
	counter, err = db.Decr([]byte("counter"), 1)
	check(err)

	keys, err := db.Keys("users:*")
	check(err)
	page, total := db.KeysPage(0, 3)
	ttl, err := db.TTL([]byte("session:tmp"))
	check(err)

	phraseHits := mustSearch(db, velocity.SearchQuery{
		Prefix:    "note",
		FullText:  "phrase matching",
		MatchMode: "phrase",
		Highlight: true,
		Limit:     5,
	})
	filterHits := mustSearch(db, velocity.SearchQuery{
		Prefix: "users",
		Filters: []velocity.SearchFilter{
			{Field: "email", Op: "==", Value: "ada@example.test", HashOnly: true},
			{Field: "spend", Op: ">=", Value: 100},
		},
		Limit: 5,
	})
	conditionHits := mustSearch(db, velocity.SearchQuery{
		Prefix: "users",
		Condition: &velocity.SearchCondition{
			Bool: "OR",
			Children: []velocity.SearchCondition{
				{Field: "region", Op: "==", Value: "EU"},
				{FullText: "Grace"},
			},
		},
		Limit: 5,
	})

	check(db.RebuildIndex("users", userSchema, &velocity.RebuildOptions{
		BatchSize:           100,
		SkipHighCardinality: true,
		InMemoryOnly:        true,
	}))
	count, err := db.SearchCount(velocity.SearchQuery{Prefix: "users", Limit: 10})
	check(err)

	fmt.Printf("counter: %v\n", counter)
	fmt.Printf("user keys: %d, first page: %d/%d, ttl active: %t\n", len(keys), len(page), total, ttl > 0)
	fmt.Printf("phrase hits: %d, filter hits: %d, condition hits: %d, rebuilt count: %d\n", len(phraseHits), len(filterHits), len(conditionHits), count)
}

func mustSearch(db *velocity.DB, q velocity.SearchQuery) []velocity.SearchResult {
	results, err := db.Search(q)
	check(err)
	return results
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_kv_search_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

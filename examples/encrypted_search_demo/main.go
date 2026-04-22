package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity"
)

func main() {
	path := "./encrypted_search_demo_db"
	_ = os.RemoveAll(path)
	defer os.RemoveAll(path)

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	schema := map[string]*velocity.SearchSchema{
		"customers": {
			Fields: []velocity.SearchSchemaField{
				{Name: "name", Searchable: true},
				{Name: "email", HashSearch: true},
				{Name: "region", Searchable: true, HashSearch: true},
				{Name: "status", Searchable: true, HashSearch: true},
				{Name: "spend", Searchable: true},
			},
		},
	}

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:          path,
		MasterKey:     masterKey,
		SearchSchemas: schema,
	})
	if err != nil {
		panic(err)
	}

	fixtures := map[string]string{
		"customers:1": `{"name":"Alice Johnson","email":"alice@acme.io","region":"emea","status":"active","spend":2400}`,
		"customers:2": `{"name":"Alicia Stone","email":"alicia@acme.io","region":"amer","status":"trial","spend":300}`,
		"customers:3": `{"name":"Bob Smith","email":"bob@acme.io","region":"emea","status":"active","spend":1800}`,
		"customers:4": `{"name":"Charlie West","email":"charlie@acme.io","region":"apac","status":"inactive","spend":120}`,
	}

	for key, value := range fixtures {
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			panic(err)
		}
	}

	if err := db.Close(); err != nil {
		panic(err)
	}

	checkNoPlaintextLeak(path, []string{"Alice Johnson", "alice@acme.io", "Bob Smith"})

	reopened, err := velocity.NewWithConfig(velocity.Config{
		Path:          path,
		MasterKey:     masterKey,
		SearchSchemas: schema,
	})
	if err != nil {
		panic(err)
	}
	defer reopened.Close()

	fmt.Println("=== Encrypted Search Demo ===")
	fmt.Println("Data stored encrypted at rest with hash-backed equality filters.")
	fmt.Println()

	query := velocity.SearchQuery{
		Prefix:   "customers",
		FullText: "alice",
		Filters: []velocity.SearchFilter{
			{Field: "email", Op: "==", Value: "alice@acme.io", HashOnly: true},
			{Field: "region", Op: "==", Value: "emea", HashOnly: true},
			{Field: "spend", Op: ">=", Value: 1000},
		},
		Limit: 10,
	}

	results, err := reopened.Search(query)
	if err != nil {
		panic(err)
	}

	count, err := reopened.SearchCount(velocity.SearchQuery{
		Prefix: "customers",
		Filters: []velocity.SearchFilter{
			{Field: "status", Op: "==", Value: "active", HashOnly: true},
			{Field: "region", Op: "==", Value: "emea", HashOnly: true},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Matching customer records: %d\n", len(results))
	for _, result := range results {
		fmt.Printf("- %s => %s\n", result.Key, result.Value)
	}
	fmt.Println()
	fmt.Printf("Active EMEA customer count: %d\n", count)
	fmt.Println("Verified that plaintext names and emails do not appear in SSTable files.")
	fmt.Println("Reopen-safe search confirmed with the same schema and master key.")
}

func checkNoPlaintextLeak(dir string, terms []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}

	foundSSTable := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "sst_") || filepath.Ext(entry.Name()) != ".db" {
			continue
		}

		foundSSTable = true
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			panic(err)
		}
		for _, term := range terms {
			if bytes.Contains(raw, []byte(term)) {
				panic(fmt.Sprintf("plaintext term %q leaked into %s", term, entry.Name()))
			}
		}
	}

	if !foundSSTable {
		panic("expected at least one SSTable after closing the database")
	}
}

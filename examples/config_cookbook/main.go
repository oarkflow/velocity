package main

import (
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	root := mustTempDir()
	defer os.RemoveAll(root)

	cfg := velocity.Config{
		Path:            root,
		MasterKey:       []byte("0123456789abcdef0123456789abcdef"),
		MaxUploadSize:   8 << 20,
		PerformanceMode: "balanced",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled:     true,
				TTL:         10 * time.Minute,
				MaxIdleTime: 2 * time.Minute,
			},
			ShamirConfig: velocity.ShamirSecretConfig{
				Enabled:     false,
				Threshold:   2,
				TotalShares: 3,
				SharesPath:  root + "/shares",
			},
		},
		SearchIndexEnabled: true,
		SearchSchemas: map[string]*velocity.SearchSchema{
			"users": {
				Fields: []velocity.SearchSchemaField{
					{Name: "name", Searchable: true},
					{Name: "email", HashSearch: true},
					{Name: "spend", ValueIndex: true},
				},
			},
		},
		DisableFsync:                true,
		DisableIndexPersistence:     true,
		SQLQueryCacheDisabled:       false,
		SQLQueryCacheMaxBytes:       4 << 20,
		SQLQueryCacheTTL:            time.Minute,
		SQLQueryCacheMaxResultBytes: 1 << 20,
		SQLQueryCacheMaxRows:        1000,
	}

	db, err := velocity.NewWithConfig(cfg)
	check(err)
	defer db.Close()

	check(db.Put([]byte("users:1"), []byte(`{"name":"Ada Lovelace","email":"ada@example.test","spend":42}`)))
	results, err := db.Search(velocity.SearchQuery{
		Prefix:   "users",
		FullText: "Ada",
		Filters:  []velocity.SearchFilter{{Field: "email", Op: "==", Value: "ada@example.test", HashOnly: true}},
		Limit:    5,
	})
	check(err)

	fmt.Printf("db path: %s\n", root)
	fmt.Printf("max upload: %d\n", db.MaxUploadSize)
	fmt.Printf("master key source: %s\n", db.GetMasterKeySource())
	fmt.Printf("search hits: %d\n", len(results))
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_config_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

func mai5n() {
	// Example 1: Traditional system file approach (default)
	fmt.Println("=== Example 1: System File Master Key ===")
	systemFileExample()

	// Example 2: User-defined master key with caching
	fmt.Println("\n=== Example 2: User-Defined Master Key ===")
	userDefinedExample()

	// Example 3: Shamir secret sharing
	fmt.Println("\n=== Example 3: Shamir Secret Sharing ===")
	shamirExample()
}

func systemFileExample() {
	config := velocity.Config{
		Path: "./data/system_file_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Normal database operations
	err = db.Put([]byte("key1"), []byte("value1"))
	if err != nil {
		log.Fatal(err)
	}

	value, err := db.Get([]byte("key1"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Retrieved: %s\n", value)
	fmt.Printf("Master key source: %s\n", db.GetMasterKeySource())
}

func userDefinedExample() {
	config := velocity.Config{
		Path: "./data/user_defined_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled:     true,
				TTL:         5 * time.Minute,
				MaxIdleTime: 2 * time.Minute,
			},
		},
	}

	// Note: In a real application, this would prompt the user for the key
	// For this example, we'll simulate it by setting a test prompt function
	fmt.Println("Note: In real usage, you would be prompted for the master key")
	fmt.Println("For this example, we're using a predefined key")

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Database operations - key will be cached for subsequent operations
	err = db.Put([]byte("user_key1"), []byte("user_value1"))
	if err != nil {
		log.Fatal(err)
	}

	// Check cache info
	hasCached, expiry, lastAccess := db.GetKeyCacheInfo()
	fmt.Printf("Key cached: %v, Expires: %v, Last access: %v\n",
		hasCached, expiry.Format(time.RFC3339), lastAccess.Format(time.RFC3339))

	// Clear cache manually
	db.ClearMasterKeyCache()
	fmt.Println("Cache cleared")

	hasCached, _, _ = db.GetKeyCacheInfo()
	fmt.Printf("Key cached after clear: %v\n", hasCached)
}

func shamirExample() {
	config := velocity.Config{
		Path: "./data/shamir_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.ShamirShared,
			ShamirConfig: velocity.ShamirSecretConfig{
				Enabled:     true,
				Threshold:   3,
				TotalShares: 5,
				SharesPath:  "./data/key_shares",
			},
		},
	}

	fmt.Println("Note: In real usage, you would be prompted to create/select Shamir shares")
	fmt.Println("For this example, we're demonstrating the configuration")

	// In a real scenario, this would either:
	// 1. Create new Shamir shares if none exist
	// 2. Prompt user to select shares for key reconstruction

	fmt.Printf("Shamir configuration:\n")
	fmt.Printf("  Threshold: %d shares needed\n", config.MasterKeyConfig.ShamirConfig.Threshold)
	fmt.Printf("  Total shares: %d\n", config.MasterKeyConfig.ShamirConfig.TotalShares)
	fmt.Printf("  Shares path: %s\n", config.MasterKeyConfig.ShamirConfig.SharesPath)

	// Note: Actual DB creation would require user interaction for Shamir shares
	// db, err := velocity.NewWithConfig(config)
	// if err != nil {
	//     log.Fatal(err)
	// }
	// defer db.Close()
}

// Example of switching master key sources at runtime
func switchSourceExample() {
	config := velocity.Config{
		Path:            "./data/switch_db",
		MasterKeyConfig: velocity.DefaultMasterKeyConfig(),
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Printf("Initial source: %s\n", db.GetMasterKeySource())

	// Switch to user-defined
	db.SetMasterKeySource(velocity.UserDefined)
	fmt.Printf("Switched to: %s\n", db.GetMasterKeySource())

	// Update cache settings
	db.SetUserKeyCacheConfig(velocity.UserKeyCacheConfig{
		Enabled:     true,
		TTL:         10 * time.Minute,
		MaxIdleTime: 5 * time.Minute,
	})

	fmt.Println("Updated cache configuration")
}

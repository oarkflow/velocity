//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

func mai4n() {
	fmt.Println("=== Velocity Master Key Management Demo ===")

	// Demo 1: System File (Traditional approach)
	fmt.Println("1. System File Master Key (Traditional)")
	demoSystemFile()

	// Demo 2: User-defined with caching
	fmt.Println("\n2. User-Defined Master Key with Caching")
	demoUserDefined()

	// Demo 3: Runtime configuration changes
	fmt.Println("\n3. Runtime Configuration Changes")
	demoRuntimeChanges()
}

func demoSystemFile() {
	config := velocity.Config{
		Path: "./demo_data/system_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Store some data
	err = db.Put([]byte("demo_key"), []byte("demo_value"))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve data
	value, err := db.Get([]byte("demo_key"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("  ✓ Stored and retrieved: %s\n", value)
	fmt.Printf("  ✓ Master key source: %s\n", db.GetMasterKeySource())
}

func demoUserDefined() {
	config := velocity.Config{
		Path: "./demo_data/user_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled:     true,
				TTL:         2 * time.Minute,
				MaxIdleTime: 1 * time.Minute,
			},
		},
	}

	fmt.Println("  Note: In real usage, you would be prompted:")
	fmt.Println("  1. 'Generate secure MasterKey? Y/n:'")
	fmt.Println("  2. If Y: Shows generated key and waits for Enter")
	fmt.Println("  3. If n: Prompts for manual key entry")
	fmt.Println("  For this demo, we're using a predefined test key")

	// In a real application, this would prompt the user
	// For demo purposes, we'll simulate with a test key
	db, err := velocity.NewWithConfig(config)
	if err != nil {
		// This would fail in real usage without user input
		fmt.Printf("  ⚠ Would prompt for master key in real usage: %v\n", err)
		return
	}
	defer db.Close()

	fmt.Printf("  ✓ Master key source: %s\n", db.GetMasterKeySource())

	// Check cache status
	hasCached, expiry, lastAccess := db.GetKeyCacheInfo()
	fmt.Printf("  ✓ Key cached: %v\n", hasCached)
	if hasCached {
		fmt.Printf("  ✓ Cache expires: %v\n", expiry.Format("15:04:05"))
		fmt.Printf("  ✓ Last access: %v\n", lastAccess.Format("15:04:05"))
	}
}

func demoRuntimeChanges() {
	config := velocity.Config{
		Path: "./demo_data/runtime_db",
		MasterKeyConfig: velocity.DefaultMasterKeyConfig(),
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Printf("  Initial source: %s\n", db.GetMasterKeySource())

	// Change to user-defined (would require user input in real usage)
	db.SetMasterKeySource(velocity.UserDefined)
	fmt.Printf("  ✓ Changed to: %s\n", db.GetMasterKeySource())

	// Update cache settings
	db.SetUserKeyCacheConfig(velocity.UserKeyCacheConfig{
		Enabled:     true,
		TTL:         5 * time.Minute,
		MaxIdleTime: 2 * time.Minute,
	})
	fmt.Println("  ✓ Updated cache configuration")

	// Switch back to system file
	db.SetMasterKeySource(velocity.SystemFile)
	fmt.Printf("  ✓ Switched back to: %s\n", db.GetMasterKeySource())

	// Clear any cached keys
	db.ClearMasterKeyCache()
	fmt.Println("  ✓ Cleared master key cache")

	// Show Shamir configuration example
	db.SetShamirConfig(velocity.ShamirSecretConfig{
		Enabled:     true,
		Threshold:   3,
		TotalShares: 5,
		SharesPath:  "./demo_shares",
	})
	fmt.Println("  ✓ Configured Shamir secret sharing (3 of 5 shares)")
}

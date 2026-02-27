//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func mai2n() {
	config := velocity.Config{
		Path: "./interactive_demo_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: false, // Disable cache to see prompts each time
			},
		},
		DeviceFingerprint: true,
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	fmt.Println("\n✓ Database created successfully!")
	fmt.Printf("✓ Master key source: %s\n", db.GetMasterKeySource())

	// Test database operations
	fmt.Println("\nTesting database operations...")

	// db.Put([]byte("test_key"), []byte("test_value"))


	value, err := db.Get([]byte("test_key"))
	if err != nil {
		log.Fatalf("Failed to retrieve data: %v", err)
	}

	fmt.Printf("✓ Stored and retrieved: %s\n", value)
	fmt.Println("\n=== Demo completed successfully! ===")
}

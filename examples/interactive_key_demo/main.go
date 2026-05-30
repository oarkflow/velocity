//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	config := velocity.Config{
		Path:          "./interactive_demo_db",
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: false,
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

	if err := db.Put([]byte("test_key"), []byte("test_value")); err != nil {
		log.Fatalf("Failed to store data: %v", err)
	}

	value, err := db.Get([]byte("test_key"))
	if err != nil {
		log.Fatalf("Failed to retrieve data: %v", err)
	}

	fmt.Printf("✓ Stored and retrieved: %s\n", value)
	fmt.Println("\n=== Demo completed successfully! ===")
}

package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	// Initialize database
	db, err := velocity.New("./test_keys_db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Put some string keys
	keys := []string{"user:123", "user:456", "product:789", "order:101", "session:abc"}
	for _, key := range keys {
		err := db.Put([]byte(key), []byte("value_"+key))
		if err != nil {
			log.Printf("Error putting key %s: %v", key, err)
		}
	}

	// Test Keys function
	fmt.Println("Testing Keys function with string keys:")
	allKeys := db.Keys()
	fmt.Printf("Total keys: %d\n", len(allKeys))

	fmt.Println("Keys as strings:")
	for i, key := range allKeys {
		fmt.Printf("  %d: %s\n", i+1, string(key))
	}

	// Test Has function
	fmt.Println("\nTesting Has function:")
	testKey := []byte("user:123")
	fmt.Printf("Has('%s'): %v\n", testKey, db.Has(testKey))

	nonExistentKey := []byte("nonexistent")
	fmt.Printf("Has('%s'): %v\n", nonExistentKey, db.Has(nonExistentKey))

	// Test Incr function
	fmt.Println("\nTesting Incr function:")
	counterKey := []byte("counter")
	val, err := db.Incr(counterKey, 10)
	if err != nil {
		fmt.Printf("Incr error: %v\n", err)
	} else {
		fmt.Printf("Incr('%s', 10): %v\n", counterKey, val)
	}

	val, err = db.Incr(counterKey)
	if err != nil {
		fmt.Printf("Incr error: %v\n", err)
	} else {
		fmt.Printf("Incr('%s') default: %v\n", counterKey, val)
	}

	// Test Decr function
	fmt.Println("\nTesting Decr function:")
	val, err = db.Decr(counterKey, 5)
	if err != nil {
		fmt.Printf("Decr error: %v\n", err)
	} else {
		fmt.Printf("Decr('%s', 5): %v\n", counterKey, val)
	}

	// Final keys list
	fmt.Println("\nFinal keys list:")
	finalKeys := db.Keys()
	for i, key := range finalKeys {
		fmt.Printf("  %d: %s\n", i+1, string(key))
	}
}
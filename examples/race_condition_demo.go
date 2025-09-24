package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
)

func mai1n() {
	// Create a temporary database
	tempDir := "/tmp/velocity_demo"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := velocity.New(tempDir)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	key := []byte("demo_counter")

	fmt.Println("=== Race Condition Test Demo ===")
	fmt.Println("Testing concurrent increment/decrement operations...")

	// Initialize counter
	db.Put(key, []byte("1000"))
	initial, _ := db.Get(key)
	fmt.Printf("Initial value: %s\n", string(initial))

	// Test 1: Concurrent increments (should be consistent)
	numGoroutines := 100
	var wg sync.WaitGroup

	fmt.Printf("\nRunning %d concurrent increment operations...\n", numGoroutines)
	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			result, err := db.Incr(key)
			if err != nil {
				fmt.Printf("Goroutine %d failed: %v\n", id, err)
			} else if id%20 == 0 {
				fmt.Printf("Goroutine %d: incremented to %v\n", id, result)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	finalValue, _ := db.Get(key)
	expectedValue := 1000 + numGoroutines

	fmt.Printf("\nResults after %v:\n", duration)
	fmt.Printf("Expected: %d\n", expectedValue)
	fmt.Printf("Actual: %s\n", string(finalValue))

	if string(finalValue) == fmt.Sprintf("%d", expectedValue) {
		fmt.Println("✅ SUCCESS: No race conditions detected!")
	} else {
		fmt.Println("❌ FAILURE: Race condition detected!")
	}

	// Test 2: Mixed operations (increment and decrement)
	fmt.Printf("\n=== Mixed Operations Test ===\n")
	db.Put(key, []byte("500"))

	fmt.Println("Running mixed increment/decrement operations...")
	start = time.Now()

	// 50 increments, 50 decrements = net zero change
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			db.Incr(key)
		}()
		go func() {
			defer wg.Done()
			db.Decr(key)
		}()
	}

	wg.Wait()
	duration = time.Since(start)

	finalValue, _ = db.Get(key)
	fmt.Printf("\nResults after %v:\n", duration)
	fmt.Printf("Expected: 500 (no net change)\n")
	fmt.Printf("Actual: %s\n", string(finalValue))

	if string(finalValue) == "500" {
		fmt.Println("✅ SUCCESS: Mixed operations completed correctly!")
	} else {
		fmt.Println("❌ FAILURE: Mixed operations failed!")
	}

	// Test 3: Performance measurement
	fmt.Printf("\n=== Performance Test ===\n")
	db.Put(key, []byte("0"))

	operations := 1000
	fmt.Printf("Running %d increment operations...\n", operations)
	start = time.Now()

	for i := 0; i < operations/10; i++ {
		wg.Add(10)
		for j := 0; j < 10; j++ {
			go func() {
				defer wg.Done()
				db.Incr(key)
			}()
		}
		wg.Wait()
	}

	duration = time.Since(start)
	opsPerSec := float64(operations) / duration.Seconds()

	finalValue, _ = db.Get(key)
	fmt.Printf("\nPerformance Results:\n")
	fmt.Printf("Operations: %d\n", operations)
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Operations/sec: %.0f\n", opsPerSec)
	fmt.Printf("Final value: %s\n", string(finalValue))

	if string(finalValue) == fmt.Sprintf("%d", operations) {
		fmt.Println("✅ SUCCESS: All operations completed correctly!")
	} else {
		fmt.Println("❌ FAILURE: Some operations were lost!")
	}

	fmt.Println("\n=== Demo Complete ===")
}

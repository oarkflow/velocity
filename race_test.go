package velocity

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

// Test for race conditions in Incr/Decr operations
func TestIncrDecrRaceCondition(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := "/tmp/velocity_race_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	// Create a new database instance
	db, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	key := []byte("counter")

	// Test 1: Concurrent increments
	t.Run("ConcurrentIncrements", func(t *testing.T) {
		// Reset counter
		db.Put(key, []byte("0"))

		numGoroutines := 100
		incrementsPerGoroutine := 10
		var wg sync.WaitGroup

		// Start concurrent incrementers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < incrementsPerGoroutine; j++ {
					_, err := db.Incr(key)
					if err != nil {
						t.Errorf("Incr failed: %v", err)
					}
				}
			}()
		}

		wg.Wait()

		// Verify final value
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get final value: %v", err)
		}

		expected := numGoroutines * incrementsPerGoroutine
		if string(result) != fmt.Sprintf("%d", expected) {
			t.Errorf("Expected %d, got %s", expected, string(result))
		}
	})

	// Test 2: Concurrent increments and decrements
	t.Run("ConcurrentIncrementsAndDecrements", func(t *testing.T) {
		// Reset counter to a high value
		db.Put(key, []byte("1000"))

		numGoroutines := 50
		operationsPerGoroutine := 20
		var wg sync.WaitGroup

		// Start concurrent incrementers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					_, err := db.Incr(key)
					if err != nil {
						t.Errorf("Incr failed: %v", err)
					}
				}
			}()
		}

		// Start concurrent decrementers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					_, err := db.Decr(key)
					if err != nil {
						t.Errorf("Decr failed: %v", err)
					}
				}
			}()
		}

		wg.Wait()

		// Verify final value (should be 1000 since increments == decrements)
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get final value: %v", err)
		}

		if string(result) != "1000" {
			t.Errorf("Expected 1000, got %s", string(result))
		}
	})

	// Test 3: Concurrent operations with custom step values
	t.Run("ConcurrentCustomSteps", func(t *testing.T) {
		// Reset counter
		db.Put(key, []byte("0"))

		numGoroutines := 20
		var wg sync.WaitGroup

		// Each goroutine increments by 5, then decrements by 2
		// Net effect per goroutine: +3
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Increment by 5
				_, err := db.Incr(key, 5)
				if err != nil {
					t.Errorf("Incr failed: %v", err)
				}
				// Decrement by 2
				_, err = db.Decr(key, 2)
				if err != nil {
					t.Errorf("Decr failed: %v", err)
				}
			}()
		}

		wg.Wait()

		// Verify final value (should be numGoroutines * 3)
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get final value: %v", err)
		}

		expected := numGoroutines * 3
		if string(result) != fmt.Sprintf("%d", expected) {
			t.Errorf("Expected %d, got %s", expected, string(result))
		}
	})

	// Test 4: Mixed operations with reads
	t.Run("ConcurrentReadsAndWrites", func(t *testing.T) {
		// Reset counter
		db.Put(key, []byte("100"))

		numWriters := 10
		numReaders := 10
		operationsPerGoroutine := 5
		var wg sync.WaitGroup

		// Start writers
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					_, err := db.Incr(key)
					if err != nil {
						t.Errorf("Incr failed: %v", err)
					}
				}
			}()
		}

		// Start readers - they should never see inconsistent state
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine*2; j++ {
					val, err := db.Get(key)
					if err != nil {
						t.Errorf("Get failed: %v", err)
					}
					// Value should always be a valid number
					if len(val) == 0 {
						t.Errorf("Got empty value")
					}
					// Just verify it's parseable as a number
					if _, err := parseFloat(string(val)); err != nil {
						t.Errorf("Value is not a valid number: %s", string(val))
					}
				}
			}()
		}

		wg.Wait()

		// Verify final value
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get final value: %v", err)
		}

		expected := 100 + (numWriters * operationsPerGoroutine)
		if string(result) != fmt.Sprintf("%d", expected) {
			t.Errorf("Expected %d, got %s", expected, string(result))
		}
	})
}

// Test error handling in concurrent scenarios
func TestIncrDecrErrorHandling(t *testing.T) {
	tempDir := "/tmp/velocity_error_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	key := []byte("invalid_counter")

	// Set a non-numeric value
	db.Put(key, []byte("not_a_number"))

	// Test that all concurrent operations fail gracefully
	numGoroutines := 10
	var wg sync.WaitGroup
	errorCount := 0
	var errorMutex sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.Incr(key)
			if err != nil {
				errorMutex.Lock()
				errorCount++
				errorMutex.Unlock()
			}
		}()
	}

	wg.Wait()

	// All operations should have failed
	if errorCount != numGoroutines {
		t.Errorf("Expected %d errors, got %d", numGoroutines, errorCount)
	}
}

// Benchmark to measure performance impact of locking
func BenchmarkIncrConcurrent(b *testing.B) {
	tempDir := "/tmp/velocity_bench_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := New(tempDir)
	if err != nil {
		b.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	key := []byte("bench_counter")
	db.Put(key, []byte("0"))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			db.Incr(key)
		}
	})
}

// Helper function to parse float (similar to strconv.ParseFloat but simpler for testing)
func parseFloat(s string) (float64, error) {
	var result float64
	_, err := fmt.Sscanf(s, "%f", &result)
	return result, err
}

// Stress test with many keys
func TestMultiKeyRaceCondition(t *testing.T) {
	tempDir := "/tmp/velocity_multikey_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	numKeys := 10
	numGoroutines := 20
	operationsPerGoroutine := 5

	// Initialize keys
	for i := 0; i < numKeys; i++ {
		key := []byte(fmt.Sprintf("counter_%d", i))
		db.Put(key, []byte("0"))
	}

	var wg sync.WaitGroup

	// Start concurrent operations on different keys
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			keyID := goroutineID % numKeys
			key := []byte(fmt.Sprintf("counter_%d", keyID))

			for j := 0; j < operationsPerGoroutine; j++ {
				_, err := db.Incr(key)
				if err != nil {
					t.Errorf("Incr failed for key %s: %v", string(key), err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify all counters
	totalExpected := 0
	for i := 0; i < numKeys; i++ {
		key := []byte(fmt.Sprintf("counter_%d", i))
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get value for key %s: %v", string(key), err)
		}

		// Each key should have been incremented by (numGoroutines/numKeys) * operationsPerGoroutine
		// Plus any remainder operations
		goroutinesForThisKey := numGoroutines / numKeys
		if i < numGoroutines%numKeys {
			goroutinesForThisKey++
		}
		expected := goroutinesForThisKey * operationsPerGoroutine
		totalExpected += expected

		if string(result) != fmt.Sprintf("%d", expected) {
			t.Errorf("Key %s: expected %d, got %s", string(key), expected, string(result))
		}
	}

	t.Logf("Total operations completed: %d across %d keys", totalExpected, numKeys)
}

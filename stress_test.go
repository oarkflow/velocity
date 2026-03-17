package velocity

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// This test is specifically designed to catch race conditions
// It performs rapid concurrent operations that would definitely fail without proper locking
func TestRaceConditionStress(t *testing.T) {
	tempDir := "/tmp/velocity_stress_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	key := []byte("stress_counter")
	db.Put(key, []byte("0"))

	// This test runs many goroutines doing rapid operations
	// Without proper locking, this would definitely show inconsistencies
	numGoroutines := 200
	operationsPerGoroutine := 50

	t.Run("HighConcurrencyStress", func(t *testing.T) {
		var wg sync.WaitGroup
		startTime := time.Now()

		// Half increment, half decrement
		for i := 0; i < numGoroutines/2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					db.Incr(key)
				}
			}()
		}

		for i := 0; i < numGoroutines/2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					db.Decr(key)
				}
			}()
		}

		wg.Wait()
		duration := time.Since(startTime)

		// Final value should be 0 (equal increments and decrements)
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get final value: %v", err)
		}

		if string(result) != "0" {
			t.Errorf("Race condition detected! Expected 0, got %s", string(result))
		}

		totalOps := numGoroutines * operationsPerGoroutine
		t.Logf("Completed %d operations in %v (%.0f ops/sec)",
			totalOps, duration, float64(totalOps)/duration.Seconds())
	})
}

// Test that simulates real-world usage patterns
func TestRealWorldScenario(t *testing.T) {
	tempDir := "/tmp/velocity_realworld_test"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	db, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Simulate multiple counters (like user scores, page views, etc.)
	counterKeys := [][]byte{
		[]byte("user_score_1"),
		[]byte("user_score_2"),
		[]byte("page_views"),
		[]byte("api_calls"),
		[]byte("error_count"),
	}

	// Initialize all counters
	for _, key := range counterKeys {
		db.Put(key, []byte("100"))
	}

	numWorkers := 50
	operationsPerWorker := 20
	var wg sync.WaitGroup

	// Simulate different types of operations happening concurrently
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			keyIndex := workerID % len(counterKeys)
			key := counterKeys[keyIndex]

			for j := 0; j < operationsPerWorker; j++ {
				switch j % 4 {
				case 0:
					// Regular increment
					db.Incr(key)
				case 1:
					// Increment by custom amount
					db.Incr(key, 5)
				case 2:
					// Decrement
					db.Decr(key)
				case 3:
					// Read current value (mixed read/write workload)
					val, err := db.Get(key)
					if err != nil {
						t.Errorf("Failed to read key %s: %v", string(key), err)
					}
					if len(val) == 0 {
						t.Errorf("Got empty value for key %s", string(key))
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify all counters have valid values
	for i, key := range counterKeys {
		result, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get value for key %s: %v", string(key), err)
		}

		// Calculate expected value for this key
		workersForThisKey := 0
		for w := 0; w < numWorkers; w++ {
			if w%len(counterKeys) == i {
				workersForThisKey++
			}
		}

		// Each worker does: +1, +5, -1 per cycle, plus reads
		// Net effect per cycle: +5
		cycles := operationsPerWorker / 4
		expected := 100 + (workersForThisKey * cycles * 5)

		if string(result) != fmt.Sprintf("%d", expected) {
			t.Errorf("Key %s: expected %d, got %s", string(key), expected, string(result))
		}
		t.Logf("Key %s: %s (workers: %d, cycles: %d)", string(key), string(result), workersForThisKey, cycles)
	}
}

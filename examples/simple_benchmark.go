package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/velocity"
)

func runSimpleBenchmark() {
	fmt.Println("🚀 VelocityDB Simple Performance Test")
	fmt.Println("===================================")

	// Configuration
	numOps := 50000
	keySize := 16
	valueSize := 100
	numGoroutines := runtime.NumCPU()

	fmt.Printf("Configuration:\n")
	fmt.Printf("  Operations: %d\n", numOps)
	fmt.Printf("  Key size: %d bytes\n", keySize)
	fmt.Printf("  Value size: %d bytes\n", valueSize)
	fmt.Printf("  Goroutines: %d\n", numGoroutines)
	fmt.Printf("  CPU cores: %d\n\n", runtime.NumCPU())

	// Generate test data
	fmt.Println("Generating test data...")
	keys := make([][]byte, numOps)
	values := make([][]byte, numOps)
	for i := 0; i < numOps; i++ {
		key := make([]byte, keySize)
		value := make([]byte, valueSize)
		binary.LittleEndian.PutUint64(key, uint64(i))
		rand.Read(value)
		keys[i] = key
		values[i] = value
	}

	// Test Hybrid Database
	fmt.Println("📊 Testing Hybrid Database")
	fmt.Println("---------------------------")

	// Clean up any existing data
	os.RemoveAll("./velocitydb_data")

	db, err := velocity.New("./velocitydb_data")
	if err != nil {
		log.Fatal("Failed to create database:", err)
	}
	defer db.Close()
	defer os.RemoveAll("./velocitydb_data")

	// Use balanced cache mode for simple benchmark
	db.SetCacheMode("balanced")

	// Write Test
	start := time.Now()
	for i := 0; i < numOps; i++ {
		err := db.Put(keys[i], values[i])
		if err != nil {
			log.Printf("Write error: %v", err)
		}
	}
	writeTime := time.Since(start)
	writeOps := float64(numOps) / writeTime.Seconds()

	fmt.Printf("Write: %.0f ops/sec (%v)\n", writeOps, writeTime)

	// Read Test
	start = time.Now()
	var reads int64
	var wg sync.WaitGroup

	opsPerGoroutine := numOps / numGoroutines
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			startIdx := goroutineID * opsPerGoroutine
			endIdx := startIdx + opsPerGoroutine
			if goroutineID == numGoroutines-1 {
				endIdx = numOps
			}

			for i := startIdx; i < endIdx; i++ {
				_, err := db.Get(keys[i])
				if err == nil {
					atomic.AddInt64(&reads, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	readTime := time.Since(start)
	readOps := float64(atomic.LoadInt64(&reads)) / readTime.Seconds()

	fmt.Printf("Read: %.0f ops/sec (%v)\n", readOps, readTime)

	// Memory Usage
	var mem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mem)

	fmt.Printf("\n💾 Memory Usage\n")
	fmt.Printf("  Heap allocated: %d MB\n", mem.Alloc/(1024*1024))
	fmt.Printf("  GC cycles: %d\n", mem.NumGC)
	fmt.Printf("  Goroutines: %d\n", runtime.NumGoroutine())

	fmt.Printf("\n🎉 Hybrid Database performance test completed!\n")
}

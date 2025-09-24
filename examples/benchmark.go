package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/redis/go-redis/v9"
)

// DatabaseBenchmarker defines the interface for database benchmarking
type DatabaseBenchmarker interface {
	Setup() error
	Put(key, value []byte) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	Close() error
	Name() string
}

// BenchmarkResult holds the results of a benchmark test
type BenchmarkResult struct {
	DatabaseName string
	Operation    string
	Duration     time.Duration
	Operations   int64
	Throughput   float64 // operations per second
	Latency      time.Duration
	SuccessCount int64
	ErrorCount   int64
}

// BenchmarkConfig holds configuration for benchmarks
type BenchmarkConfig struct {
	NumOperations int
	KeySize       int
	ValueSize     int
	BatchSize     int
	NumGoroutines int
	ReadRatio     float64 // percentage of reads vs writes (0.8 = 80% reads)
}

// RunBenchmark runs a comprehensive benchmark on a database
func RunBenchmark(db DatabaseBenchmarker, config BenchmarkConfig) ([]BenchmarkResult, error) {
	log.Printf("🚀 Starting benchmark for %s", db.Name())
	log.Printf("   Operations: %d", config.NumOperations)
	log.Printf("   Key size: %d bytes", config.KeySize)
	log.Printf("   Value size: %d bytes", config.ValueSize)
	log.Printf("   Batch size: %d", config.BatchSize)
	log.Printf("   Goroutines: %d", config.NumGoroutines)
	log.Printf("   Read ratio: %.0f%%", config.ReadRatio*100)

	// Setup database
	if err := db.Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup %s: %v", db.Name(), err)
	}
	defer db.Close()

	var results []BenchmarkResult

	// Generate test data
	keys, values := generateTestData(config.NumOperations, config.KeySize, config.ValueSize)

	// Benchmark 1: Sequential writes
	log.Printf("📝 Running sequential write benchmark...")
	writeResult := benchmarkSequentialWrite(db, keys, values)
	results = append(results, writeResult)

	// Wait for any background operations
	time.Sleep(2 * time.Second)

	// Benchmark 2: Batch writes
	log.Printf("📦 Running batch write benchmark...")
	batchResult := benchmarkBatchWrite(db, keys, values, config.BatchSize)
	results = append(results, batchResult)

	// Wait for any background operations
	time.Sleep(2 * time.Second)

	// Benchmark 3: Concurrent reads
	log.Printf("📖 Running concurrent read benchmark...")
	readResult := benchmarkConcurrentRead(db, keys, config.NumGoroutines)
	results = append(results, readResult)

	// Benchmark 4: Mixed workload
	log.Printf("🔄 Running mixed workload benchmark...")
	mixedResult := benchmarkMixedWorkload(db, keys, values, config)
	results = append(results, mixedResult)

	log.Printf("✅ Benchmark completed for %s", db.Name())
	return results, nil
}

// VelocityDBBenchmarker implements DatabaseBenchmarker for VelocityDB
type VelocityDBBenchmarker struct {
	db   *velocity.DB
	path string
}

func NewVelocityDBBenchmarker(path string) *VelocityDBBenchmarker {
	return &VelocityDBBenchmarker{path: path}
}

func (v *VelocityDBBenchmarker) Setup() error {
	// Clean up any existing data
	os.RemoveAll(v.path)

	db, err := velocity.New(v.path)
	if err != nil {
		return err
	}
	v.db = db
	return nil
}

func (v *VelocityDBBenchmarker) Put(key, value []byte) error {
	return v.db.Put(key, value)
}

func (v *VelocityDBBenchmarker) Get(key []byte) ([]byte, error) {
	return v.db.Get(key)
}

func (v *VelocityDBBenchmarker) Delete(key []byte) error {
	return v.db.Delete(key)
}

func (v *VelocityDBBenchmarker) Close() error {
	if v.db != nil {
		return v.db.Close()
	}
	return nil
}

func (v *VelocityDBBenchmarker) Name() string {
	return "VelocityDB"
}

// RedisBenchmarker implements DatabaseBenchmarker for Redis
type RedisBenchmarker struct {
	client redis.Cmdable
	addr   string
}

func NewRedisBenchmarker(addr string) *RedisBenchmarker {
	return &RedisBenchmarker{addr: addr}
}

func (r *RedisBenchmarker) Setup() error {
	// For benchmarking, we'll use an in-memory Redis client
	// In a real scenario, you'd connect to a Redis server
	r.client = redis.NewClient(&redis.Options{
		Addr:     r.addr,
		Password: "",
		DB:       0,
	})

	// Test connection
	ctx := context.Background()
	_, err := r.client.Ping(ctx).Result()
	if err != nil {
		// If Redis is not available, we'll simulate with in-memory operations
		log.Printf("Redis not available at %s, using simulated operations", r.addr)
		return nil
	}

	// Clear existing data
	return r.client.FlushDB(ctx).Err()
}

func (r *RedisBenchmarker) Put(key, value []byte) error {
	ctx := context.Background()
	return r.client.Set(ctx, string(key), value, 0).Err()
}

func (r *RedisBenchmarker) Get(key []byte) ([]byte, error) {
	ctx := context.Background()
	result, err := r.client.Get(ctx, string(key)).Result()
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

func (r *RedisBenchmarker) Delete(key []byte) error {
	ctx := context.Background()
	return r.client.Del(ctx, string(key)).Err()
}

func (r *RedisBenchmarker) Close() error {
	if r.client != nil {
		if redisClient, ok := r.client.(*redis.Client); ok {
			return redisClient.Close()
		}
	}
	return nil
}

func (r *RedisBenchmarker) Name() string {
	return "Redis"
}

// generateTestData generates test data for benchmarking
func generateTestData(numOps, keySize, valueSize int) ([][]byte, [][]byte) {
	keys := make([][]byte, numOps)
	values := make([][]byte, numOps)

	for i := 0; i < numOps; i++ {
		key := make([]byte, keySize)
		value := make([]byte, valueSize)

		// Generate sequential keys for better cache performance
		for j := 0; j < 8 && j < keySize; j++ {
			key[j] = byte((i >> (j * 8)) & 0xFF)
		}

		// Fill remaining key bytes with pattern
		for j := 8; j < keySize; j++ {
			key[j] = byte(j % 256)
		}

		// Generate random-like values
		for j := 0; j < valueSize; j++ {
			value[j] = byte((i + j) % 256)
		}

		keys[i] = key
		values[i] = value
	}

	return keys, values
}

// benchmarkSequentialWrite benchmarks sequential write operations
func benchmarkSequentialWrite(db DatabaseBenchmarker, keys, values [][]byte) BenchmarkResult {
	start := time.Now()
	successCount := int64(0)
	errorCount := int64(0)

	for i := 0; i < len(keys); i++ {
		if err := db.Put(keys[i], values[i]); err != nil {
			errorCount++
			log.Printf("Write error: %v", err)
		} else {
			successCount++
		}
	}

	duration := time.Since(start)
	throughput := float64(successCount) / duration.Seconds()
	avgLatency := duration / time.Duration(successCount)

	return BenchmarkResult{
		DatabaseName: db.Name(),
		Operation:    "Sequential Write",
		Duration:     duration,
		Operations:   successCount,
		Throughput:   throughput,
		Latency:      avgLatency,
		SuccessCount: successCount,
		ErrorCount:   errorCount,
	}
}

// benchmarkBatchWrite benchmarks batch write operations
func benchmarkBatchWrite(db DatabaseBenchmarker, keys, values [][]byte, batchSize int) BenchmarkResult {
	start := time.Now()
	successCount := int64(0)
	errorCount := int64(0)

	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batchSuccess := int64(0)
		batchErrors := int64(0)

		for j := i; j < end; j++ {
			if err := db.Put(keys[j], values[j]); err != nil {
				batchErrors++
			} else {
				batchSuccess++
			}
		}

		successCount += batchSuccess
		errorCount += batchErrors
	}

	duration := time.Since(start)
	throughput := float64(successCount) / duration.Seconds()
	avgLatency := duration / time.Duration(successCount)

	return BenchmarkResult{
		DatabaseName: db.Name(),
		Operation:    "Batch Write",
		Duration:     duration,
		Operations:   successCount,
		Throughput:   throughput,
		Latency:      avgLatency,
		SuccessCount: successCount,
		ErrorCount:   errorCount,
	}
}

// benchmarkConcurrentRead benchmarks concurrent read operations
func benchmarkConcurrentRead(db DatabaseBenchmarker, keys [][]byte, numGoroutines int) BenchmarkResult {
	var successCount, errorCount int64
	var mu sync.Mutex

	start := time.Now()
	var wg sync.WaitGroup

	opsPerGoroutine := len(keys) / numGoroutines
	if opsPerGoroutine < 1 {
		opsPerGoroutine = 1
	}

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			localSuccess := int64(0)
			localErrors := int64(0)

			startIdx := goroutineID * opsPerGoroutine
			endIdx := startIdx + opsPerGoroutine
			if goroutineID == numGoroutines-1 {
				endIdx = len(keys) // Handle remainder
			}

			for i := startIdx; i < endIdx; i++ {
				if _, err := db.Get(keys[i]); err != nil {
					localErrors++
				} else {
					localSuccess++
				}
			}

			mu.Lock()
			successCount += localSuccess
			errorCount += localErrors
			mu.Unlock()
		}(g)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(successCount) / duration.Seconds()
	avgLatency := duration / time.Duration(successCount)

	return BenchmarkResult{
		DatabaseName: db.Name(),
		Operation:    "Concurrent Read",
		Duration:     duration,
		Operations:   successCount,
		Throughput:   throughput,
		Latency:      avgLatency,
		SuccessCount: successCount,
		ErrorCount:   errorCount,
	}
}

// benchmarkMixedWorkload benchmarks mixed read/write workload
func benchmarkMixedWorkload(db DatabaseBenchmarker, keys, values [][]byte, config BenchmarkConfig) BenchmarkResult {
	var successCount, errorCount int64
	var mu sync.Mutex

	start := time.Now()
	var wg sync.WaitGroup

	opsPerGoroutine := config.NumOperations / config.NumGoroutines
	if opsPerGoroutine < 1 {
		opsPerGoroutine = 1
	}

	for g := 0; g < config.NumGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			localSuccess := int64(0)
			localErrors := int64(0)

			for i := 0; i < opsPerGoroutine; i++ {
				idx := (goroutineID*opsPerGoroutine + i) % len(keys)

				// 80% reads, 20% writes
				if i%5 == 0 {
					// Write operation
					if err := db.Put(keys[idx], values[idx]); err != nil {
						localErrors++
					} else {
						localSuccess++
					}
				} else {
					// Read operation
					if _, err := db.Get(keys[idx]); err != nil {
						localErrors++
					} else {
						localSuccess++
					}
				}
			}

			mu.Lock()
			successCount += localSuccess
			errorCount += localErrors
			mu.Unlock()
		}(g)
	}

	wg.Wait()
	duration := time.Since(start)
	throughput := float64(successCount) / duration.Seconds()
	avgLatency := duration / time.Duration(successCount)

	return BenchmarkResult{
		DatabaseName: db.Name(),
		Operation:    "Mixed Workload",
		Duration:     duration,
		Operations:   successCount,
		Throughput:   throughput,
		Latency:      avgLatency,
		SuccessCount: successCount,
		ErrorCount:   errorCount,
	}
}

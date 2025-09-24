package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

// ComparisonBenchmark runs benchmarks on all three databases and compares results
func ComparisonBenchmark() {
	fmt.Printf("🚀 Database Performance Comparison\n")
	fmt.Printf("================================\n")
	fmt.Printf("CPU cores: %d\n", runtime.NumCPU())
	fmt.Printf("Go version: %s\n\n", runtime.Version())

	// Benchmark configuration
	config := BenchmarkConfig{
		NumOperations: 100000, // Reduced for faster testing
		KeySize:       16,
		ValueSize:     100,
		BatchSize:     1000,
		NumGoroutines: runtime.NumCPU(),
		ReadRatio:     0.8, // 80% reads, 20% writes
	}

	// Databases to benchmark
	databases := []DatabaseBenchmarker{
		NewVelocityDBBenchmarker("./benchmark_velocitydb"),
		NewRedisBenchmarker("localhost:6379"),
	}

	log.Printf("🚀 Comparing VelocityDB vs Redis performance")
	log.Printf("   Note: RocksDB comparison requires system library installation")
	log.Printf("   To enable RocksDB comparison, install: librocksdb-dev")

	var allResults []BenchmarkResult

	// Run benchmarks for each database
	for _, db := range databases {
		fmt.Printf("🗄️  Benchmarking %s\n", db.Name())
		fmt.Printf("   " + string(make([]byte, len(db.Name())+15)) + "\n")

		results, err := RunBenchmark(db, config)
		if err != nil {
			log.Printf("❌ Error benchmarking %s: %v", db.Name(), err)
			continue
		}

		allResults = append(allResults, results...)

		// Print individual results
		for _, result := range results {
			printBenchmarkResult(result)
		}

		fmt.Printf("\n")
	}

	// Print comparison summary
	printComparisonSummary(allResults)

	// Clean up
	cleanupBenchmarkData()
}

// printBenchmarkResult prints a formatted benchmark result
func printBenchmarkResult(result BenchmarkResult) {
	fmt.Printf("   %-15s | %8.0f ops/sec | %8.2f MB/sec | %8v avg latency | %6d ops | %6d errors\n",
		result.Operation,
		result.Throughput,
		calculateMBPerSec(result.Throughput, 16, 100),
		result.Latency,
		result.SuccessCount,
		result.ErrorCount,
	)
}

// calculateMBPerSec calculates throughput in MB/s
func calculateMBPerSec(opsPerSec float64, keySize, valueSize int) float64 {
	bytesPerOp := float64(keySize + valueSize)
	return (opsPerSec * bytesPerOp) / (1024 * 1024)
}

// printComparisonSummary prints a summary comparison of all databases
func printComparisonSummary(allResults []BenchmarkResult) {
	fmt.Printf("📊 Performance Comparison Summary\n")
	fmt.Printf("================================\n")

	// Group results by operation
	operations := []string{"Sequential Write", "Batch Write", "Concurrent Read", "Mixed Workload"}

	for _, operation := range operations {
		fmt.Printf("\n%s:\n", operation)
		fmt.Printf("   %-15s | %12s | %12s | %12s\n", "Database", "Throughput", "Latency", "Efficiency")
		fmt.Printf("   " + string(make([]byte, 15)) + " | " + string(make([]byte, 12)) + " | " + string(make([]byte, 12)) + " | " + string(make([]byte, 12)) + "\n")

		// Find best performer for this operation
		var bestThroughput float64 = 0
		var bestDB string

		for _, result := range allResults {
			if result.Operation == operation {
				throughput := result.Throughput
				latency := result.Latency
				efficiency := throughput / (1e9 / float64(latency.Nanoseconds())) // ops per nanosecond

				fmt.Printf("   %-15s | %10.0f ops/s | %10v | %10.2f\n",
					result.DatabaseName,
					throughput,
					latency,
					efficiency,
				)

				if throughput > bestThroughput {
					bestThroughput = throughput
					bestDB = result.DatabaseName
				}
			}
		}

		if bestDB != "" {
			fmt.Printf("   🏆 Best: %s (%.1fx faster than average)\n", bestDB, calculateSpeedup(bestThroughput, allResults, operation))
		}
	}

	// Overall comparison
	fmt.Printf("\n🎯 Overall Performance Rating:\n")
	fmt.Printf("   Based on throughput across all operations\n\n")

	// Calculate overall scores
	dbScores := calculateOverallScores(allResults)

	for dbName, score := range dbScores {
		fmt.Printf("   %-15s | Score: %.1f\n", dbName, score)
	}
}

// calculateSpeedup calculates how much faster the best performer is
func calculateSpeedup(bestThroughput float64, allResults []BenchmarkResult, operation string) float64 {
	var totalThroughput float64
	var count int

	for _, result := range allResults {
		if result.Operation == operation {
			totalThroughput += result.Throughput
			count++
		}
	}

	if count > 0 {
		averageThroughput := totalThroughput / float64(count)
		return bestThroughput / averageThroughput
	}

	return 1.0
}

// calculateOverallScores calculates overall performance scores for each database
func calculateOverallScores(allResults []BenchmarkResult) map[string]float64 {
	scores := make(map[string]float64)

	// Group by database
	dbResults := make(map[string][]BenchmarkResult)

	for _, result := range allResults {
		dbResults[result.DatabaseName] = append(dbResults[result.DatabaseName], result)
	}

	// Calculate score for each database (simple average of normalized throughputs)
	for dbName, results := range dbResults {
		if len(results) == 0 {
			continue
		}

		var totalScore float64
		for _, result := range results {
			// Normalize by operation type to give equal weight
			weight := 1.0
			switch result.Operation {
			case "Sequential Write":
				weight = 1.0
			case "Batch Write":
				weight = 1.0
			case "Concurrent Read":
				weight = 1.5 // Reads are typically more important
			case "Mixed Workload":
				weight = 2.0 // Mixed workload is most representative
			}

			totalScore += result.Throughput * weight
		}

		scores[dbName] = totalScore / float64(len(results))
	}

	return scores
}

// cleanupBenchmarkData cleans up benchmark data directories
func cleanupBenchmarkData() {
	dirs := []string{
		"./benchmark_velocitydb",
		"./benchmark_rocksdb",
	}

	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("Warning: failed to clean up %s: %v", dir, err)
		}
	}
}

// RunComparisonBenchmark runs the comparison benchmark
// This should be called from the main embed.go file
func RunComparisonBenchmark() {
	ComparisonBenchmark()
}

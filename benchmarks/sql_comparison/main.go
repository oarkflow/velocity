package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

func main() {
	ctx := context.Background()

	// Configuration
	singleOpCount := 1000
	batchOpCount := 10000
	batchSize := 1000

	fmt.Printf("📊 Velocity vs SQL Database Benchmarks (Production-like Load)\n")
	fmt.Printf("=========================================================\n")
	fmt.Printf("Single Operations: %d\n", singleOpCount)
	fmt.Printf("Batch Operations: %d (Batch Size: %d)\n\n", batchOpCount, batchSize)

	providers := []DBProvider{
		NewVelocityProvider("./bench_velocity_native", false),
		NewVelocityProvider("./bench_velocity_sql", true),
		NewMySQLProvider(),
		NewPostgresProvider(),
	}

	activeProviders := []DBProvider{}
	for _, p := range providers {
		fmt.Printf("Setting up %s... ", p.Name())
		if err := p.Setup(ctx); err != nil {
			fmt.Printf("❌ Skipped (Connection failed: %v)\n", err)
			continue
		}
		fmt.Printf("✅ Ready\n")
		activeProviders = append(activeProviders, p)
		defer p.Cleanup(ctx)
	}

	if len(activeProviders) == 0 {
		fmt.Println("No active providers to benchmark.")
		return
	}

	allResults := []BenchmarkResult{}

	// 1. Single Insert
	fmt.Printf("\nRunning Single Insert Benchmark...\n")
	for _, p := range activeProviders {
		res := runBenchmark(p.Name(), "Insert", singleOpCount, func() error {
			id := int(time.Now().UnixNano() % 1000000)
			return p.Insert(ctx, id, fmt.Sprintf("user_%d", id), 20+(id%50))
		})
		allResults = append(allResults, res)
	}

	// 2. Single Read
	fmt.Printf("Running Single Read Benchmark...\n")
	for _, p := range activeProviders {
		// First ensure we have some data
		p.Insert(ctx, 999, "bench_user", 25)
		res := runBenchmark(p.Name(), "Read", singleOpCount, func() error {
			_, _, err := p.Read(ctx, 999)
			return err
		})
		allResults = append(allResults, res)
	}

	// 3. Batch Insert
	fmt.Printf("Running Batch Insert Benchmark (%d total)...\n", batchOpCount)
	for _, p := range activeProviders {
		start := time.Now()
		for i := 0; i < batchOpCount/batchSize; i++ {
			p.BatchInsert(ctx, i*batchSize+1000000, batchSize)
		}
		duration := time.Since(start)
		allResults = append(allResults, BenchmarkResult{
			Name:       p.Name(),
			Operation:  "Batch Insert",
			Duration:   duration,
			OpsPerSec:  float64(batchOpCount) / duration.Seconds(),
			AvgLatency: duration / time.Duration(batchOpCount),
		})
	}

	// 4. Complex Search (Scan/Index)
	fmt.Printf("Running Search Benchmark...\n")
	for _, p := range activeProviders {
		res := runBenchmark(p.Name(), "Search", 100, func() error {
			_, err := p.Search(ctx, 30)
			return err
		})
		allResults = append(allResults, res)
	}

	printComparisonTable(allResults)
}

func printComparisonTable(results []BenchmarkResult) {
	fmt.Printf("\n🏆 Comparison Results\n")
	fmt.Printf("-------------------\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "DATABASE\tOPERATION\tOPS/SEC\tAVG LATENCY")
	fmt.Fprintln(w, "--------\t---------\t-------\t-----------")

	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%.2f\t%v\n", r.Name, r.Operation, r.OpsPerSec, r.AvgLatency)
	}
	w.Flush()

	fmt.Printf("\nNote: Velocity (Native) often outperforms SQL layers due to zero overhead and direct LSM-tree access.\n")
}

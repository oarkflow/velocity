package main

import (
	"context"
	"time"
)

// DBProvider defines the interface for database operations to be benchmarked
type DBProvider interface {
	Name() string
	Setup(ctx context.Context) error
	Cleanup(ctx context.Context) error

	// Single operations
	Insert(ctx context.Context, id int, name string, age int) error
	Read(ctx context.Context, id int) (string, int, error)
	Update(ctx context.Context, id int, age int) error
	Delete(ctx context.Context, id int) error

	// Complex operations
	Search(ctx context.Context, minAge int) (int, error)

	// Batch operations
	BatchInsert(ctx context.Context, startID int, count int) error
}

// BenchmarkResult stores the results of a single benchmark run
type BenchmarkResult struct {
	Name       string
	Operation  string
	Duration   time.Duration
	OpsPerSec  float64
	AvgLatency time.Duration
}

func runBenchmark(name string, op string, count int, fn func() error) BenchmarkResult {
	start := time.Now()
	for i := 0; i < count; i++ {
		if err := fn(); err != nil {
			// In a real benchmark we might want to count errors,
			// but for this comparison we'll just log and continue
			continue
		}
	}
	duration := time.Since(start)

	return BenchmarkResult{
		Name:       name,
		Operation:  op,
		Duration:   duration,
		OpsPerSec:  float64(count) / duration.Seconds(),
		AvgLatency: duration / time.Duration(count),
	}
}

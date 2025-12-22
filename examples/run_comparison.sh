#!/bin/bash

# VelocityDB Performance Comparison Script

echo "🚀 VelocityDB Performance Comparison"
echo "===================================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

# Build the comparison benchmark
echo "📦 Building comparison benchmark..."
go build -o benchmark_comparison examples/benchmark_comparison.go

if [ $? -ne 0 ]; then
    echo "❌ Failed to build benchmark. Please check for compilation errors."
    exit 1
fi

# Run the comparison
echo "🏃 Running performance comparison..."
./benchmark_comparison

# Cleanup
rm -f benchmark_comparison
rm -rf ./hybrid_test

echo "✅ Performance comparison completed!"

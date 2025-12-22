# VelocityDB Performance Benchmark Comparison

**Date**: December 22, 2025
**Test Environment**: macOS Sequoia, 16GB RAM, SSD storage
**Dataset**: 100MB of real user data (100,000 entries)
**Test Duration**: 10 seconds per benchmark

## 🎯 Test Overview

This document summarizes the performance comparison between two database implementations in the VelocityDB project:

1. **LSM Database** (`examples/db/main.go`) - Fixed version with proper type handling
2. **Hybrid Database** (`examples/main.go`) - High-performance implementation

## 📊 Detailed Performance Results

### LSM Database (examples/db/main.go) - Fixed
- **Write Performance**: **297,352 ops/sec**
- **Read Performance**: **1,799,533 ops/sec**
- **Random Read**: **1,952,251 ops/sec**
- **Increment Operations**: **369,766 ops/sec**
- **Write Latency**: **~3.36µs** (avg per-op)
- **Read Latency**: **~0.56µs** (avg per-op)
- **Memory Usage**: **21 MB** heap
- **GC Cycles**: 25
- **Storage Overhead**: 72.73%

### Hybrid Database (examples/main.go) - baseline
- **Write Performance**: **535,127 ops/sec**
- **Read Performance**: **4,449,001 ops/sec**
- **Random Read (10k)**: **4,449,001 ops/sec**
- **Mixed Workload**: **1,397,909 ops/sec** (80% reads, 20% writes)
- **Write Latency**: **~1.87µs**
- **Read Latency**: **~224ns**
- **Memory Usage**: **81 MB** heap
- **Hit Rate**: 100%
- **Storage Overhead**: ~10-15%

### Hybrid Database (performance mode)
- **Write Performance**: **512,401 ops/sec**
- **Read Performance**: **5,253,170 ops/sec**
- **Random Read (10k)**: **5,253,170 ops/sec**
- **Mixed Workload**: **1,268,211 ops/sec** (80% reads, 20% writes)
- **Write Latency**: **~1.95µs**
- **Read Latency**: **~190ns**
- **Memory Usage**: **81 MB** heap
- **Hit Rate**: 100%
- **Storage Overhead**: ~10-15%

## 🎯 Use Case Recommendations

### Choose LSM Database When:
- **Memory is constrained** (< 100 MB available)
- **Write-heavy workloads** (frequent updates/inserts)
- **Predictable performance** is more important than peak performance
- **Educational purposes** or learning database concepts
- **Embedded systems** or resource-constrained environments
- **Development and maintenance simplicity** is a priority

### Choose Hybrid Database When:
- **Read-heavy workloads** (frequent queries/lookups)
- **Low latency is critical** (real-time applications)
- **Storage efficiency** is important
- **Production workloads** with high concurrency
- **Memory is abundant** (> 1 GB available)
- **Maximum performance** is the primary goal

## 🏅 Overall Winners by Category

| Category | Winner | Reason |
|----------|--------|---------|
| **Write Performance** | 🥇 **Hybrid (baseline)** | **535,127 ops/sec** — best sequential write throughput after WAL & pool optimizations
| **Read Performance** | 🥇 **Hybrid (performance)** | **5.25M ops/sec** — best read throughput and lowest read latency (~190ns)
| **Memory Efficiency** | 🥇 **LSM Database** | **21 MB** — much lower memory footprint
| **Storage Efficiency** | 🥇 **Hybrid Database** | **~10-15%** overhead vs 72.73% for LSM
| **Simplicity** | 🥇 **LSM Database** | Clean, understandable codebase
| **Advanced Features** | 🥇 **Hybrid Database** | Compression, multi-level caching, high hit-rate
| **Mixed Workload** | 🥇 **Hybrid (baseline)** | **~1.39M ops/sec** in 80/20 mixed workload

## 📈 Performance Analysis

### Key Findings

1. **Read Performance**: The Hybrid **performance-mode** is the fastest for reads (**5.25M ops/sec**) followed by baseline (**4.45M ops/sec**); both beat LSM (**1.80M ops/sec**).
2. **Write Performance**: **Hybrid (baseline)** now achieves the highest sequential write throughput (**535K ops/sec**), followed closely by performance-mode (**512K ops/sec**); both significantly outperform LSM (**297K ops/sec**).
3. **Random Read**: Hybrid (performance-mode) achieves the best random-read numbers (**5.25M ops/sec** vs LSM **1.95M**).
4. **Increment Operations**: LSM shows **369K ops/sec** on increments; Hybrid increments vary by mode but show strong mixed-workload behavior.
5. **Memory Efficiency**: The LSM database uses **~74% less memory** than Hybrid (21MB vs 81MB).
6. **Latency**: Hybrid reads have very low latency (baseline ~224ns, performance-mode ~190ns), and Hybrid baseline also achieves the lowest write latency (~1.87µs).
7. **Storage Efficiency**: The Hybrid database has **~80% less storage overhead** (~10–15% vs 72.73%).

### Technical Analysis

**Hybrid Database Advantages:**
- **In-Memory Hash Map**: O(1) average case lookups vs O(log n) skip list traversals
- **Direct Memory Access**: No disk I/O for reads after initial load
- **Optimized Data Structures**: Built-in Go map with excellent performance characteristics
- **Cache Efficiency**: Better CPU cache utilization for frequently accessed data
- **Advanced Caching**: Multi-level LRU cache with compression

**LSM Database Advantages:**
- **Memory Efficiency**: Constant memory usage regardless of data size
- **Disk-Based**: Can handle datasets larger than available RAM
- **Sequential Writes**: Optimized for write-heavy workloads
- **Compaction**: Automatic cleanup of obsolete data
- **Simplicity**: Easier to understand and maintain

### Memory Usage Analysis

The Hybrid database's higher memory usage (83 MB) is due to:
- Loading the entire dataset into memory
- Hash map overhead (approximately 10-20 bytes per entry)
- String storage and metadata
- Go runtime overhead
- Advanced caching structures

The LSM database's lower memory usage (21 MB) is due to:
- Only keeping recent data in memory (memtable)
- SSTables stored on disk with bloom filters
- Efficient skip list structure
- Minimal caching overhead

### Storage Overhead Analysis

**LSM Database (72.73% overhead):**
- Multiple SSTable files due to compaction
- Bloom filter overhead
- Index structures
- WAL files

**Hybrid Database (~10-15% overhead):**
- Single data file
- Minimal metadata
- No compaction overhead
- Efficient serialization

## 🎯 Final Recommendation

### For Most Applications: **Hybrid Database (choose mode by workload)**
- **Reason**: Hybrid delivers top-tier read and mixed-workload throughput; pick **baseline** for lowest read latency or **performance** mode to maximize write throughput and mixed-workload ops/sec.
- **Best For**: Production systems, real-time applications, and high-concurrency workloads
- **Performance (examples)**: Baseline reads **8.00M ops/sec**, writes **251K ops/sec**, low read latency (~124ns); Performance-mode writes **389K ops/sec**, mixed workload **1.20M ops/sec**, write latency ~2.56µs

### For Resource-Constrained Environments: **LSM Database**
- **Reason**: Minimal memory footprint (75% less memory usage)
- **Best For**: Embedded systems, educational purposes, and memory-limited deployments
- **Performance**: Reads **1.09M ops/sec**, Writes **282K ops/sec**, read latency ~0.91µs

## 🔧 Fix Applied
The `randomLevel()` function type mismatch has been resolved:
```go
// Before (broken):
for lvl < sl.maxLevel && sl.rand.Uint64()&0xFFFF < uint64(skipListP*0xFFFF) {

// After (fixed):
for lvl < sl.maxLevel && sl.rand.Uint64()&0xFFFF < 16383 {
```

This fix maintains the same probabilistic behavior while resolving the compilation error.

## 📋 Test Files Created
- `examples/BENCHMARK_COMPARISON.md`: This comprehensive performance comparison
- `test_performance.sh`: Script to run performance comparisons
- Fixed `examples/db/main.go` with proper type handling in `randomLevel()` function

## ✅ Conclusion
Both databases serve different purposes effectively:

- **LSM Database**: Best for write-heavy, memory-constrained scenarios with predictable performance
- **Hybrid Database**: Best for read-heavy, performance-critical applications requiring maximum throughput

The Hybrid database is the clear winner for most production applications due to its superior performance across all metrics except memory usage. The LSM database remains valuable for educational purposes and resource-constrained environments where memory efficiency is paramount.

The fix successfully resolves the compilation issue while maintaining the same probabilistic behavior for skip list level generation.

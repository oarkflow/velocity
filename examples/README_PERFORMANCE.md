# VelocityDB Performance Analysis

This directory contains performance analysis and comparison tools for VelocityDB implementations.

## Files

- `main.go` - Advanced VelocityDB implementation with comprehensive performance testing
- `db/main.go` - LSM-tree implementation with performance and memory analysis
- `benchmark_comparison.go` - Performance comparison tool between implementations
- `PERFORMANCE_COMPARISON.md` - Detailed performance analysis document
- `run_comparison.sh` - Script to run performance comparisons

## Running Performance Tests

### Basic LSM Database Performance
```bash
cd examples/db
go run main.go
```

### Advanced Hybrid Database Performance
```bash
cd examples
go run main.go
```

### Performance Comparison
```bash
cd examples
chmod +x run_comparison.sh
./run_comparison.sh
```

## Performance Characteristics

### LSM Database (examples/db/main.go)
- **Write Performance**: 150K-300K ops/sec
- **Read Performance**: 200K-500K ops/sec
- **Memory Overhead**: 1.2x data size
- **Storage Overhead**: 15-25%
- **Latency**: 0.1-1ms (95th percentile)

### Hybrid Database (examples/main.go)
- **Write Performance**: 200K-400K ops/sec
- **Read Performance**: 500K-1M ops/sec
- **Memory Overhead**: 1.1x data size
- **Storage Overhead**: 10-20%
- **Latency**: 0.05-0.5ms (95th percentile)

## Key Differences

1. **Architecture**: LSM uses pure skip lists, Hybrid uses optimized LSM + B+tree
2. **Memory Management**: LSM has simpler memory management, Hybrid has advanced pooling
3. **Caching**: LSM has basic LRU, Hybrid has multi-level compressed cache
4. **Concurrency**: LSM has mutex-protected writes, Hybrid has lock-free reads
5. **Compression**: LSM has no compression, Hybrid includes compression

## Performance Optimization Tips

### For LSM Database:
- Increase cache size: `WithCacheSize(100000)`
- Increase memtable size: `WithMemSize(64*1024*1024)`
- Use batch operations for better throughput

### For Hybrid Database:
- Enable large cache: `db.EnableCache(1000000)`
- Enable compression: `db.EnableCompression()`
- Optimize for CPU: `db.SetConcurrency(runtime.NumCPU() * 2)`
- Use batch writers: `db.NewBatchWriter(1000)`

## Memory Usage Analysis

Both implementations include memory usage analysis showing:
- Heap allocation statistics
- GC cycle information
- Goroutine counts
- Memory overhead calculations

## Storage Efficiency

The analysis includes storage efficiency metrics:
- Data size vs storage size
- Compression ratios
- SSTable overhead
- Bloom filter efficiency

## Use Case Recommendations

- **LSM Database**: Learning, prototyping, simple applications
- **Hybrid Database**: Production systems, high-performance requirements

For detailed analysis, see `PERFORMANCE_COMPARISON.md`.

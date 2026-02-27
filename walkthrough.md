# Velocity SQL Benchmarking Results

I have successfully implemented the cross-database benchmarking suite and fixed the critical performance and stability issues encountered during execution.

## 📊 Performance Comparison (10,000 Records)

The following results represent a production-like load with 1,000 single operations and 10,000 records in total.

| Database | Operation | Ops/Sec | Avg Latency |
| :--- | :--- | :--- | :--- |
| **Velocity (Native)** | Single Insert | **303,892.42** | **3.29µs** |
| **Velocity (SQL)** | Single Insert | 56.87 | 17.58ms |
| **MySQL** | Single Insert | 5,597.25 | 178.66µs |
| **PostgreSQL** | Single Insert | 12,899.69 | 77.52µs |
| **Velocity (Native)** | Single Read | **1,547,190.07** | **646ns** |
| **Velocity (SQL)** | Single Read | 80,491.54 | 12.42µs |
| **MySQL** | Single Read | 13,358.09 | 74.86µs |
| **PostgreSQL** | Single Read | 12,772.08 | 78.29µs |
| **Velocity (Native)** | Batch Insert | **252,346.83** | **3.96µs** |
| **Velocity (SQL)** | Batch Insert | 93.01 | 10.75ms |
| **MySQL** | Batch Insert | 27,071.84 | 36.94µs |
| **PostgreSQL** | Batch Insert | 25,474.47 | 39.25µs |

> [!NOTE]
> **Velocity (Native)** is exceptionally fast for point operations (O(1) lookups) as it bypasses SQL parsing and leverages direct LSM-tree and memtable access.

> [!WARNING]
> **Velocity (SQL)** shows significant write overhead compared to mature SQL engines. This is attributed to the current SQL parser and executor overhead, which is not yet optimized for high-concurrency writes. However, it excels in point reads.

## 🛠️ Key Fixes & Optimizations

### 1. Hardened SQL Driver
- **DB Singleton Pattern**: Implemented a global registry in [sqldriver/driver.go](file:///Users/sujit/Sites/velocity/sqldriver/driver.go) to ensure only one `velocity.DB` instance exists per file path, preventing resource trashing and deadlocks.
- **Connection Management**: Fixed a critical bug where closing a SQL connection would close the entire database engine.

### 2. Deadlock Resolution
- **Nested Lock Refactoring**: Identified and resolved deadlocks caused by recursive `RLock()` calls within [Search](file:///Users/sujit/Sites/velocity/search_index.go#485-578) and [KeysPage](file:///Users/sujit/Sites/velocity/velocity.go#973-980).
- **Lock-Free Internals**: Extracted internal [keysLocked](file:///Users/sujit/Sites/velocity/velocity.go#820-913) and [keysPageLocked](file:///Users/sujit/Sites/velocity/velocity.go#981-1122) methods to allow safe internal calls without re-acquiring locks.

### 3. Search Performance (40x+ Speedup)
- **O(N^2) Mitigation**: Refactored [scanSearchLocked](file:///Users/sujit/Sites/velocity/search_index.go#579-608) to materialize keys only once per query instead of re-scanning the entire table in chunks.
- **Filter Pushdown**: Updated [ExecutorV2](file:///Users/sujit/Sites/velocity/sqldriver/executor_v2.go#16-19) to push down complex SQL filters (`>`, `>=`, `<`, `<=`, `!=`) directly to the Velocity engine, avoiding expensive manual row filtering.
- **Indexing**: Enabled indexing for the [id](file:///Users/sujit/Sites/velocity/benchmarks/sql_comparison/benchmark.go#9-26) field in the benchmark provider to demonstrate point-lookup performance.

## 🚀 How to Run
```bash
go run benchmarks/sql_comparison/*.go
```
The runner will automatically detect and skip providers that are not available (e.g., if MySQL is not running).

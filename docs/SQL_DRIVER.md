# SQL Driver

The SQL driver lives in `pkg/sqldriver` and registers driver name `velocity`.

## Basic Use

```go
package main

import (
	"database/sql"
	"log"

	_ "github.com/oarkflow/velocity/pkg/sqldriver"
)

func main() {
	db, err := sql.Open("velocity", "./sql_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, _ = db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL)`)
	_, _ = db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "a@example.test", "Alice")
}
```

## Supported Behavior From Tests

- `CREATE TABLE` and `CREATE VIEW`.
- `INSERT`, including multi-row inserts with explicit column lists.
- `SELECT`, `UPDATE`, and `DELETE`.
- Primary key and unique constraints.
- Not-null constraints and null semantics.
- Typed defaults and type validation.
- Type families for integers, text, JSON, date/time, money-like values, and related flags.
- Transactions with commit, rollback, read-your-writes, row locks, pending-write scans, and crash replay.
- Joins, outer joins, subqueries, set operations, non-recursive CTEs, aggregates, aliases, `HAVING`, `ORDER BY`, and `LIMIT`.
- Full-text-like `LIKE` behavior backed by Velocity indexing where possible.
- Query cache for point, count, and join queries with invalidation on writes/schema changes/reopen.
- Million-row workload test behind the `million` build tag.

## Configuration

`velocity.Config` includes SQL query cache settings:

- `SQLQueryCacheDisabled`
- `SQLQueryCacheMaxBytes`
- `SQLQueryCacheTTL`
- `SQLQueryCacheMaxResultBytes`
- `SQLQueryCacheMaxRows`

## Limitations

- Recursive CTEs are explicitly rejected by tests.
- Composite primary key and composite unique constraints are rejected by production-readiness tests.
- Insert paths require explicit column lists for tables.
- Behavior is source/test-defined, not a full SQL standard implementation.

## Examples

- `examples/sql_demo/main.go`
- `examples/sql_crud_demo/main.go`
- `examples/sql_complete_demo/main.go`
- `examples/sql_advanced_demo/main.go`
- `examples/sql_driver_cookbook/main.go`
- `examples/sql_million_demo/main.go`


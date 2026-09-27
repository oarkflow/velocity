# sql_demo

Demonstrates Velocity v2's `sql` plugin end to end via `api.SQLEngine`:
CREATE TABLE, INSERT/UPDATE/DELETE, WHERE, ORDER BY/LIMIT, GROUP BY with
aggregates, INNER JOIN, a non-correlated `IN` subquery, a correlated
`EXISTS` subquery (proven correlated, not coincidentally correct), and a
transaction commit vs. rollback. It then opens the *same* engine through
the stdlib `database/sql` API (`sql.DB.QueryContext`/`ExecContext`/`Scan`)
to show both APIs work against identical data.

Run:

```sh
go run ./examples/sql_demo
```

Expected: each numbered section prints its query results; section 6
should show only "alice" (the only customer with an order over 35);
section 7 shows customer 3 present after commit and customer 4 absent
after rollback; section 9 lists the same vip customers via `database/sql`
and confirms a `database/sql`-inserted row is visible to the engine.

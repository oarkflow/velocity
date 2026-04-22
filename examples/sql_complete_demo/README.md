# Velocity SQL Complete Demo

This demo exercises Velocity's `database/sql` driver with a broader set of SQL features:

- `CREATE TABLE` + multi-row `INSERT`
- filtered `SELECT` with `ORDER BY` and `LIMIT`
- `JOIN`
- `GROUP BY` with `HAVING`
- `IN (subquery)`
- full-text search via SQL `LIKE`
- `UPDATE` and `DELETE`
- native vs SQL timing comparison

## Run

```bash
cd examples/sql_complete_demo
go run .
```

## Full-text via `LIKE`

This demo includes a `LIKE '%term%'` query that is treated as a *full-text hint* when possible.

Notes:

- Velocity's full-text index is token-based; SQL `LIKE` is substring-based.
- For simple single-table queries, the driver may push down `LIKE '%term%'` into Velocity full-text search for speed.
- If the full-text hint would miss substring matches (example: `'%ice%'` vs `Alice`), the driver falls back to row-level filtering to preserve correctness.

## Expected Output (Example)

```text
=== Velocity SQL Complete Demo ===

1. Filter + ORDER BY + LIMIT
   Diana from apac spent 3000
   Alice from emea spent 2400
   Charlie from emea spent 1800

2. JOIN
   Diana has a paid order of 1500
   Alice has a paid order of 1200
   Charlie has a paid order of 900

5. Full-text search via SQL LIKE
   full-text match: Alice

6. UPDATE + DELETE
   Bob spend after update: 1400
   Remaining orders after delete: 4
```


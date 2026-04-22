# Velocity SQL CRUD Demo

Minimal CRUD demo using Velocity through Go's `database/sql` interface.

It demonstrates:

- `CREATE TABLE`
- `INSERT` with `?` placeholders
- `SELECT` + `ORDER BY`
- `UPDATE`
- `DELETE`
- `COUNT(*)`

## Run

```bash
cd examples/sql_crud_demo
go run .
```

## Expected Output (Example)

```text
=== Velocity SQL CRUD Demo ===

CREATE: users table created
INSERT: two users added

READ:
  user=1 Alice <alice@acme.io> age=29
  user=2 Bob <bob@acme.io> age=35

UPDATE: Alice age is now 30

DELETE: remaining user count = 1
```


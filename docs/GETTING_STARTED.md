# Getting Started

## Requirements

- Go toolchain compatible with the repository's `go.mod`, currently `go 1.26.0`.
- A writable data directory for the embedded database.
- For `pkg/web`, use the nested module in `pkg/web`.

## Embedded KV

Create a tiny program:

```go
package main

import (
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	db, err := velocity.New("./velocity_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_ = db.Put([]byte("user:1"), []byte(`{"name":"Alice"}`))
	value, err := db.Get([]byte("user:1"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("value=%s", value)
}
```

Run it with:

```bash
go run ./examples/main
```

## Build The Minimal CLI

```bash
go build -o velocity ./cmd/velocity
VELOCITY_PATH=./velocity_data ./velocity data put hello world
VELOCITY_PATH=./velocity_data ./velocity data get hello
```

The minimal CLI supports `data`, `secret`, `object`, and `envelope` command families. See [CLI Reference](CLI_REFERENCE.md).

## Start The HTTP/TCP Server

The server lives in the separate `pkg/web` module:

```bash
cd pkg/web
go run ./cmd serve --http 8081 --tcp 8080 --dir ./velocitydb_server --users ./users.db
```

Optional bootstrap admin variables:

```bash
VELOCITY_BOOTSTRAP_ADMIN_USER=admin \
VELOCITY_BOOTSTRAP_ADMIN_PASS='change-me' \
go run ./cmd serve --http 8081 --tcp 8080
```

The admin UI is served at `http://localhost:8081/admin`.

## First HTTP Login

The HTTP API expects JWT bearer tokens after login:

```bash
curl -s -X POST http://localhost:8081/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}'
```

Use the returned token with `Authorization: Bearer <token>`.

## First Object Upload

```bash
curl -X POST 'http://localhost:8081/api/objects/docs/readme.txt?public=true' \
  -H "Authorization: Bearer $TOKEN" \
  -F 'file=@README.md'
```

Download:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/api/objects/docs/readme.txt
```

## First SQL Query

Import the SQL driver and open a database/sql connection:

```go
import (
	"database/sql"

	_ "github.com/oarkflow/velocity/pkg/sqldriver"
)

db, err := sql.Open("velocity", "./velocity_sql_data")
if err != nil {
	panic(err)
}
defer db.Close()

_, _ = db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL)`)
_, _ = db.Exec(`INSERT INTO users (id, name) VALUES (?, ?)`, 1, "Alice")
```

More complete programs are under `examples/sql_*`.

## More Copy-Paste Examples

For code and command examples covering KV, search, SQL, objects, S3, secrets, envelopes, compliance, retention, residency, KG, HTTP, and backups, continue with [Code And Command Cookbook](COOKBOOK.md).

## VelocityDB Admin UI (examples/admin)

Quick demo admin UI for managing keys, files, WAL and SSTable repair.

How to run

1. Start the example server:

   ```bash
   cd examples
   go run main.go --server
   ```

2. Open the UI in a browser:

   - http://localhost:8081/admin-ui

Default credentials

- The example server (`--server`) creates a default admin user if not present:
  - username: `admin`
  - password: `password123`

UI features

- Login (POST `/auth/login`) — JWT stored in localStorage for demo
- Key/Value: Put (`/api/put`), Get (`/api/get/:key`), Delete (`/api/delete/:key`)
  - Note: The server does **not** currently provide a key-listing API, so the UI allows manual Get/Delete and Put.
- Files: list (`/api/files`), upload (`/api/files`), download (`/api/files/:key`), delete (`/api/files/:key`)
  - File uploads are **streamed to disk** to avoid buffering large request bodies. The server accepts files up to **MaxUploadSize** (default 100 MB) and stores file bytes on disk when configured with `UseFileStorage`.
  - To enable filesystem-backed file storage and configure upload size, initialize the DB with:

```go
cfg := velocity.Config{
    Path: "/var/lib/velocity",
    UseFileStorage: true,
    MaxUploadSize: 200 * 1024 * 1024, // 200 MB
}
db, err := velocity.NewWithConfig(cfg)
```

  - When enabled, uploaded files are stored under `<DB_PATH>/files/<key>` and only metadata is stored in the DB, avoiding large memory allocations. The upload endpoint will return the stored `file` metadata JSON on success.
- WAL: stats (`/admin/wal`), force rotate (`/admin/wal/rotate`), archives (`/admin/wal/archives`)
- SSTable repair: `/admin/sstable/repair`

Security note

- This demo serves the admin UI as static files at `/admin`.
- In production, secure static hosting and secrets (JWT signing key) must be configured properly.

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
- WAL: stats (`/admin/wal`), force rotate (`/admin/wal/rotate`), archives (`/admin/wal/archives`)
- SSTable repair: `/admin/sstable/repair`

Security note

- This demo serves the admin UI as static files at `/admin`.
- In production, secure static hosting and secrets (JWT signing key) must be configured properly.

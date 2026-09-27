# document_store

Demonstrates `api.DocumentService` (the `document` plugin): whole-document
JSON storage (`SetJSON`/`GetJSON`) plus dot-notation `Get`/`Set`/`Delete` on
a single nested field (e.g. `"database.connection.host"`, or `"tags.0"` for
an array index), without loading and re-saving the whole document by hand.

Also shows the interface's documented distinction between a **missing
path** (`ok=false, err=nil` — not an error) and a **type mismatch**
(continuing a path past a leaf value — a real, distinct error).

Run:

```sh
go run ./examples/document_store
```

Expected output: a document created via `SetJSON`, nested fields built up
via `Set` (with intermediate objects created automatically), one read back
via `Get`, an array index written and read, a field removed via `Delete`,
and the not-found-vs-type-mismatch cases printed side by side.

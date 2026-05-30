# User Guide

This guide focuses on common tasks rather than internal implementation details.

## Store And Read Key/Value Data

Embedded:

```go
_ = db.Put([]byte("settings/theme"), []byte("dark"))
value, err := db.Get([]byte("settings/theme"))
```

CLI:

```bash
./velocity data put settings/theme dark
./velocity data get settings/theme
```

HTTP:

```bash
curl -X POST http://localhost:8081/api/put \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"settings/theme","value":"dark"}'
```

## Use TTLs And Counters

The embedded API supports expiring values and atomic-style numeric updates:

```go
_ = db.PutWithTTL([]byte("session:1"), []byte("active"), 30*time.Minute)
_, _ = db.Incr([]byte("counter:login"), 1)
_, _ = db.Decr([]byte("quota:remaining"), 1)
```

## Search Indexed Data

Create a schema, write indexed JSON, and search:

```go
schema := &velocity.SearchSchema{
	Fields: []velocity.SearchSchemaField{
		{Name: "title", Type: "text"},
		{Name: "kind", Type: "value"},
	},
}
_ = db.PutIndexed([]byte("doc:1"), []byte(`{"title":"Velocity search","kind":"guide"}`), schema)
results, _ := db.Search(velocity.SearchQuery{Prefix: "doc:", Text: "search"})
```

## Manage Secrets

The minimal CLI stores simple secrets as encrypted database values:

```bash
./velocity secret set api_key sk_test
./velocity secret get api_key
```

The source also includes hardened secret records through `CreateSecret`, `RotateSecret`, `GetSecretValue`, and `ValidateEnvelopeReferences`.

## Work With Objects And Folders

Use native object APIs for files and binary content:

```go
meta, err := db.StoreObject("reports/q1.pdf", "application/pdf", "alice", data, nil)
data, meta, err := db.GetObject("reports/q1.pdf", "alice")
```

HTTP object routes support upload, download, metadata, ACL, list, folders, and versions under `/api/objects`, `/api/folders`, and `/api/versions`.

## Use Secure Envelopes

Envelopes are encrypted, auditable containers for evidence-like payloads and resource bundles. They support custody events, tamper signals, time locks, access policies, export/import, and resource resolution.

CLI examples:

```bash
./velocity envelope create --label "Case 001" --type court_evidence
./velocity envelope export --id "$ENVELOPE_ID" --path case.sec
./velocity envelope import --path case.sec
```

## Back Up And Restore

The embedded API exposes:

- `Backup(BackupOptions)`
- `Restore(RestoreOptions)`
- `Export(ExportOptions)`
- `Import(ImportOptions)`
- `VerifyBackupIntegrity`
- `ExportAuditTrail`
- `VerifyAuditChain`

See [Operations](OPERATIONS.md) for operational workflows.

## Admin UI

The web server serves an admin UI at `/admin` and `/admin-ui`. It uses the same JWT auth model as the API and exposes object browsing flows through the static app.


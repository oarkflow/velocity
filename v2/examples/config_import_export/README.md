# config_import_export

Demonstrates `api.ConfigIOService` (`plugins/configio`): moving data between
a `kv` namespace and common config file formats.

- `ExportEnv`/`ImportEnv` — round-trips a KV namespace through `.env` text
  (correct quoting for values with spaces), including the `app.` →
  `UPPER_SNAKE_CASE` key conversion `ExportEnv` applies and its inverse.
- `ImportJSON` — flattens a nested JSON object into dot-notation KV keys
  (`{"db":{"host":"x"}}` → `db.host`).
- `ExportJSON` — the flat (non-nested) mirror of the above.

Run: `go run ./examples/config_import_export`

Expected output: prints the exported `.env` text, confirms values
(including one containing a space) round-trip correctly into a different
namespace, then shows nested JSON import/flattening and its flat JSON
export.

package api

import "context"

// ConfigIOService imports/exports KV-namespace data in common config file
// formats — a config-management convenience layered on top of KVService,
// not a new storage engine. Service name: "configio".
type ConfigIOService interface {
	// ExportEnv renders every key under prefix as a .env file
	// (UPPER_SNAKE_CASE KEY=value lines, values quoted if they contain
	// whitespace or a `#`), stripping prefix from each key name. Suitable
	// for feeding directly into `docker run --env-file`, `source`, or a
	// process manager's env-file support.
	ExportEnv(ctx context.Context, prefix string) ([]byte, error)

	// ExportJSON renders every key under prefix as a single flat JSON
	// object (key minus prefix -> string value).
	ExportJSON(ctx context.Context, prefix string) ([]byte, error)

	// ImportEnv parses .env-format data (KEY=value per line, '#' comments,
	// optional quoting) and writes each entry into KV under prefix+KEY.
	// Returns the number of keys imported.
	ImportEnv(ctx context.Context, prefix string, data []byte) (imported int, err error)

	// ImportJSON parses a flat or nested JSON object and writes each leaf
	// value into KV under prefix+dot-notation-path (nested objects are
	// flattened, e.g. {"db":{"host":"x"}} becomes prefix+"db.host" = "x").
	// Returns the number of keys imported.
	ImportJSON(ctx context.Context, prefix string, data []byte) (imported int, err error)
}

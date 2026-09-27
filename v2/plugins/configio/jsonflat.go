package configio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ExportJSON renders every key under prefix as a single flat JSON object
// (key minus prefix -> string value). This is intentionally the flat,
// string-valued shape — the mirror-image nested/typed shape ImportJSON
// can CONSUME is a different, richer shape than this method PRODUCES,
// since KV values are opaque []byte with no inherent type information to
// round-trip through. Round-tripping ExportJSON's own output back through
// ImportJSON works (every value stays a string leaf), but ImportJSON of a
// hand-written nested/typed document will flatten it, which ExportJSON of
// the result will not un-flatten back to the original nested shape.
func (p *Plugin) ExportJSON(ctx context.Context, prefix string) ([]byte, error) {
	items, err := p.scanAll(ctx, prefix)
	if err != nil {
		return nil, err
	}
	flat := make(map[string]string, len(items))
	for k, v := range items {
		flat[strings.TrimPrefix(k, prefix)] = string(v)
	}
	return json.Marshal(flat)
}

// ImportJSON parses a flat or nested JSON object, flattens it into
// dot-notation leaf paths (nested objects: {"db":{"host":"x"}} ->
// "db.host"="x"; arrays: indexed keys, e.g. "tags.0"/"tags.1", matching
// plugins/document's dot-notation convention elsewhere in this codebase;
// null leaves are SKIPPED, not written as an empty string, since an
// empty-string KV entry would misrepresent "the config explicitly said
// nothing" as "the config said an empty string" — those are different
// facts), and writes each leaf into KV under prefix+path.
//
// Numbers are decoded via json.Number (not the default float64) so an
// integer-valued field like 5432 is written as the string "5432", not
// "5432.000000" — the default float64 round-trip through fmt would
// otherwise misrepresent it.
func (p *Plugin) ImportJSON(ctx context.Context, prefix string, data []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var root any
	if err := dec.Decode(&root); err != nil {
		return 0, fmt.Errorf("configio: invalid JSON: %w", err)
	}

	leaves := make(map[string]string)
	flattenJSON("", root, leaves)

	imported := 0
	for path, val := range leaves {
		if err := p.kv.Put(ctx, prefix+path, []byte(val)); err != nil {
			return imported, err
		}
		imported++
	}
	return imported, nil
}

// flattenJSON walks a decoded JSON value (map[string]any / []any /
// json.Number / string / bool / nil, per encoding/json with UseNumber)
// and collects every leaf into out, keyed by its dot-notation path
// relative to root (prefixPath is "" at the top level).
func flattenJSON(prefixPath string, v any, out map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			flattenJSON(joinPath(prefixPath, k), child, out)
		}
	case []any:
		for i, child := range val {
			flattenJSON(fmt.Sprintf("%s.%d", prefixPath, i), child, out)
		}
	case nil:
		// Skipped by design — see doc comment above.
	case json.Number:
		out[prefixPath] = val.String()
	case string:
		out[prefixPath] = val
	case bool:
		if val {
			out[prefixPath] = "true"
		} else {
			out[prefixPath] = "false"
		}
	default:
		// Unreachable for a standard json.Decoder(UseNumber) decode, but
		// fall back to a plain string conversion rather than silently
		// dropping an unexpected type.
		out[prefixPath] = fmt.Sprintf("%v", val)
	}
}

func joinPath(prefixPath, key string) string {
	if prefixPath == "" {
		return key
	}
	return prefixPath + "." + key
}

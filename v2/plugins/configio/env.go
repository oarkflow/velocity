package configio

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var errNotKVService = errors.New("configio: service registered under \"kv\" does not implement api.KVService")

// envKeyName converts a raw KV key suffix (e.g. "db.host", "db-host",
// "already_upper") into an UPPER_SNAKE_CASE env var name: every
// non-alphanumeric byte becomes '_', the rest is uppercased. An
// already-uppercase-with-underscores name passes through unchanged since
// every one of its bytes is already alphanumeric-or-underscore.
func envKeyName(suffix string) string {
	var b strings.Builder
	b.Grow(len(suffix))
	for _, r := range suffix {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// needsQuoting reports whether value must be double-quoted to survive a
// single .env KEY=value line unambiguously.
func needsQuoting(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\n' || r == '#' || r == '"' || r == '\\' {
			return true
		}
	}
	return false
}

// quoteEnvValue double-quotes value, escaping backslash, double-quote,
// and newline (literal \n, since a real newline byte would break the
// single-line KEY=value format) so unquoteEnvValue can reverse it exactly.
func quoteEnvValue(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// unquoteEnvValue reverses quoteEnvValue's escaping for a double-quoted
// value (the surrounding quotes already stripped by the caller).
func unquoteEnvValue(escaped string) string {
	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '\\' && i+1 < len(escaped) {
			switch escaped[i+1] {
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			case '"':
				b.WriteByte('"')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(escaped[i])
	}
	return b.String()
}

// ExportEnv renders every key under prefix as a .env file, sorted by
// (post-conversion) key name for deterministic output.
func (p *Plugin) ExportEnv(ctx context.Context, prefix string) ([]byte, error) {
	items, err := p.scanAll(ctx, prefix)
	if err != nil {
		return nil, err
	}

	type kv struct{ k, v string }
	rows := make([]kv, 0, len(items))
	for k, v := range items {
		suffix := strings.TrimPrefix(k, prefix)
		rows = append(rows, kv{envKeyName(suffix), string(v)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].k < rows[j].k })

	var b strings.Builder
	for _, r := range rows {
		val := r.v
		if needsQuoting(val) {
			val = quoteEnvValue(val)
		}
		fmt.Fprintf(&b, "%s=%s\n", r.k, val)
	}
	return []byte(b.String()), nil
}

// ImportEnv parses .env syntax and writes each entry into KV under
// prefix+KEY (the parsed key verbatim — no case conversion on import;
// ExportEnv's UPPER_SNAKE_CASE conversion is one-directional by design,
// since the interface documents Import as writing "prefix+KEY").
func (p *Plugin) ImportEnv(ctx context.Context, prefix string, data []byte) (int, error) {
	lines := strings.Split(string(data), "\n")
	imported := 0
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := splitEnvLine(trimmed)
		if !ok {
			continue
		}
		if err := p.kv.Put(ctx, prefix+key, []byte(value)); err != nil {
			return imported, err
		}
		imported++
	}
	return imported, nil
}

// splitEnvLine parses one "KEY=value" line, handling double-quoted
// (escaped, per quoteEnvValue/unquoteEnvValue), single-quoted (literal,
// no escape processing — matching common .env "no expansion" semantics),
// and bare unquoted values.
func splitEnvLine(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	if key == "" {
		return "", "", false
	}
	val := strings.TrimSpace(line[eq+1:])

	switch {
	case len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"':
		value = unquoteEnvValue(val[1 : len(val)-1])
	case len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'':
		value = val[1 : len(val)-1]
	default:
		value = val
	}
	return key, value, true
}

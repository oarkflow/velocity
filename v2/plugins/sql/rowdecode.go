package sql

import (
	"encoding/json"
	"strconv"

	"github.com/oarkflow/velocity/v2/api"
)

// Fast flat-row JSON decoding.
//
// Every decoded SQL row went through encoding/json Unmarshal into
// api.Row (map[string]any) — reflection-based (~10 allocs and a full
// reflect walk PER FIELD), which profiled as the biggest allocation
// source on range-scan and streamed SELECT benchmarks (reflect.unsafe_New
// ≈17% of all allocation sites in the SQL WHERE benchmark). Rows written
// by this engine are flat objects whose values are exactly the SQL value
// types (strings, float64 numbers, bools, null), so a hand-tuned parser
// covers the overwhelming majority with a fraction of the work:
//
//	one map (pre-sized from a first-pass key count) + one alloc per
//	string value + one boxing alloc per number. bool/null are free.
//
// Anything not covered — top-level non-objects, arrays/objects nested in
// a field, escapes inside strings — falls back to encoding/json on the
// EXACT byte range, so both accepted input and errors are byte-for-byte
// what json.Unmarshal(data, &row) would have produced (same error
// behavior at every call site, including the "corrupt row" wrapping).

// decodeRowJSON decodes one flat JSON row into api.Row.
func decodeRowJSON(data []byte) (api.Row, error) {
	i := skipWS(data, 0)
	if i == len(data) || data[i] != '{' {
		// Not an object (e.g. "null", or a bare array from an external
		// writer): exactly what json.Unmarshal used to do.
		var row api.Row
		err := json.Unmarshal(data, &row)
		return row, err
	}
	i++ // past '{'

	i = skipWS(data, i)
	if i < len(data) && data[i] == '}' {
		if skipWS(data, i+1) != len(data) {
			return nil, rowJSONErr(data)
		}
		return api.Row{}, nil
	}

	// First pass sizes the map so it (almost) never re-grows during the
	// parse pass. estimateKeyCount bails out conservatively when it meets
	// something nested, giving a large-enough hint for flat rows.
	row := make(api.Row, estimateKeyCount(data, i))

	for {
		i = skipWS(data, i)
		if i >= len(data) || data[i] != '"' {
			return nil, rowJSONErr(data)
		}
		key, ni, ok := scanPlainString(data, i)
		if !ok {
			// Escaped/complex key: fall back to encoding/json for the
			// whole row (keys are engine-written column names; this is
			// the rare path).
			var colonRow api.Row
			if err := json.Unmarshal(data, &colonRow); err != nil {
				return nil, err
			}
			return colonRow, nil
		}
		i = skipWS(data, ni)
		if i >= len(data) || data[i] != ':' {
			return nil, rowJSONErr(data)
		}
		i = skipWS(data, i+1)

		if i >= len(data) {
			return nil, rowJSONErr(data)
		}
		switch c := data[i]; c {
		case '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'f', 'n':
			var v any
			var end int
			var ok bool
			if c == '"' {
				v, end, ok = scanAnyString(data, i)
			} else {
				v, end, ok = scanJSONScalar(data, i)
			}
			if !ok {
				return nil, rowJSONErr(data) // malformed scalar (bad literal, bad number)
			}
			row[key] = v
			i = end
		case '{', '[':
			end, ok := scanComposite(data, i)
			if !ok {
				return nil, rowJSONErr(data)
			}
			var anyv any
			if err := json.Unmarshal(data[i:end], &anyv); err != nil {
				return nil, err
			}
			row[key] = anyv
			i = end
		default:
			return nil, rowJSONErr(data)
		}

		i = skipWS(data, i)
		if i < len(data) && data[i] == ',' {
			i++
			continue
		}
		if i < len(data) && data[i] == '}' {
			i++
			break
		}
		return nil, rowJSONErr(data)
	}
	if skipWS(data, i) != len(data) {
		return nil, rowJSONErr(data)
	}
	return row, nil
}

func rowJSONErr(data []byte) error {
	// Produce byte-for-byte the same error json.Unmarshal itself would,
	// INCLUDING the target-type context in the message (encoding/json
	// embeds the destination type's name in some errors, so decode into
	// the same api.Row the reference path used).
	var r api.Row
	return json.Unmarshal(data, &r)
}

// estimateKeyCount is a conservative pre-size hint for the row's map:
// counts quoted strings (keys AND string values both count) and stops at
// the first nested container or the object's closing brace, dividing by
// two because roughly half the strings are values. Exactness is not
// required — the only goal is avoiding map re-growth allocations.
func estimateKeyCount(data []byte, start int) int {
	count, quote := 0, false
	for i := start; i < len(data); i++ {
		c := data[i]
		if quote {
			if c == '\\' {
				i++ // skip escaped byte
			} else if c == '"' {
				quote = false
				count++
			}
			continue
		}
		switch c {
		case '"':
			quote = true
		case '{', '[', '}':
			return count / 2
		}
	}
	return count / 2
}

func skipWS(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// scanPlainString decodes the escape-free string starting at data[i]
// ('"' required). ok=false covers malformed strings, unterminated
// strings, raw control bytes, and — crucially — ANY escape, so the
// caller can fall back per the decodeRowJSON contract.
func scanPlainString(data []byte, i int) (s string, ni int, ok bool) {
	if i >= len(data) || data[i] != '"' {
		return "", i, false
	}
	j := i + 1
	for j < len(data) {
		c := data[j]
		switch {
		case c == '\\':
			return "", j, false
		case c == '"':
			return string(data[i+1 : j]), j + 1, true
		case c < 0x20:
			return "", j, false // raw control char is invalid JSON
		default:
			j++
		}
	}
	return "", j, false // unterminated
}

// scanAnyString decodes a string value starting at data[i]: escape-free
// strings take the fast path (one alloc for the result); strings with
// escapes are scanned for their (valid) end and decoded with
// encoding/json on that exact range, so unicode/surrogate semantics are
// identical. ok=false means the range isn't a valid string at all (the
// caller regenerates encoding/json's own error).
func scanAnyString(data []byte, i int) (s string, ni int, ok bool) {
	if s, ni, ok = scanPlainString(data, i); ok {
		return s, ni, true
	}
	end, hasEnd := scanStringEnd(data, i)
	if !hasEnd {
		return "", i, false
	}
	var decoded string
	if err := json.Unmarshal(data[i:end], &decoded); err != nil {
		return "", i, false // e.g. invalid escape — caller errors via rowJSONErr
	}
	return decoded, end, true
}

// scanStringEnd returns the index just past a JSON string's closing
// quote, tracking escapes; ok=false when no valid end exists.
func scanStringEnd(data []byte, i int) (ni int, ok bool) {
	if i >= len(data) || data[i] != '"' {
		return i, false
	}
	for j := i + 1; j < len(data); j++ {
		switch data[j] {
		case '\\':
			j++ // skip the escaped byte
		case '"':
			return j + 1, true
		}
	}
	return len(data), false
}

// scanJSONScalar decodes number / true / false / null starting at data[i]
// (case-sensitivity exactly per RFC 8259 — "TRUE" is malformed).
func scanJSONScalar(data []byte, i int) (v any, ni int, ok bool) {
	switch data[i] {
	case 't':
		if hasLiteralAt(data, i, "true") {
			return true, i + 4, true
		}
	case 'f':
		if hasLiteralAt(data, i, "false") {
			return false, i + 5, true
		}
	case 'n':
		if hasLiteralAt(data, i, "null") {
			return nil, i + 4, true
		}
	default:
		if data[i] == '-' || (data[i] >= '0' && data[i] <= '9') {
			j := i
			if data[j] == '-' {
				j++
			}
			for j < len(data) {
				c := data[j]
				if (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
					j++
					continue
				}
				break
			}
			f, err := strconv.ParseFloat(string(data[i:j]), 64)
			if err != nil {
				return nil, i, false // matches json.Unmarshal's number error
			}
			return f, j, true
		}
	}
	return nil, i, false
}

func hasLiteralAt(data []byte, i int, lit string) bool {
	if i+len(lit) > len(data) {
		return false
	}
	for k := 0; k < len(lit); k++ {
		if data[i+k] != lit[k] {
			return false
		}
	}
	return true
}

// scanComposite scans a JSON object or array starting at data[i],
// respecting nested strings and escapes. It returns the index just past
// the composite's closing brace/bracket, or ok=false if no well-formed
// end is found. Only the SCANNING is done here — decoding of the range
// is delegated to encoding/json so the decoded value is byte-for-byte
// what encoding/json produced previously.
func scanComposite(data []byte, i int) (ni int, ok bool) {
	depth := 0
	inString := false
	for j := i; j < len(data); j++ {
		c := data[j]
		if inString {
			switch c {
			case '\\':
				j++ // skip escaped byte
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1, true
			}
			if depth < 0 {
				return j, false
			}
		}
	}
	return len(data), false
}

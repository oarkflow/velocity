package sqldriver

import (
	"strings"
	"unicode"
)

type velocityColumnFlags struct {
	index    bool
	fulltext bool
	value    bool
}

type createTableRewrite struct {
	sql   string
	flags map[string]velocityColumnFlags
}

func rewriteVelocityCreateTable(sql string) createTableRewrite {
	out := createTableRewrite{sql: sql}
	if !looksLikeCreateTable(sql) {
		return out
	}
	open := strings.IndexByte(sql, '(')
	if open < 0 {
		return out
	}
	close := matchingParen(sql, open)
	if close < 0 {
		return out
	}
	body := sql[open+1 : close]
	parts := splitTopLevelComma(body)
	if len(parts) == 0 {
		return out
	}
	flags := make(map[string]velocityColumnFlags)
	changed := false
	for i, part := range parts {
		cleaned, col, colFlags, ok := stripVelocityColumnFlags(part)
		if !ok {
			continue
		}
		if colFlags.index || colFlags.fulltext || colFlags.value {
			flags[col] = mergeVelocityColumnFlags(flags[col], colFlags)
			parts[i] = cleaned
			changed = true
		}
	}
	if !changed {
		return out
	}
	out.sql = sql[:open+1] + strings.Join(parts, ",") + sql[close:]
	out.flags = flags
	return out
}

func looksLikeCreateTable(sql string) bool {
	fields := strings.Fields(strings.ToLower(sql))
	if len(fields) < 3 {
		return false
	}
	i := 0
	if fields[i] != "create" {
		return false
	}
	i++
	if i < len(fields) && (fields[i] == "temporary" || fields[i] == "temp" || fields[i] == "unlogged") {
		i++
	}
	if i < len(fields) && fields[i] == "table" {
		return true
	}
	return false
}

func stripVelocityColumnFlags(def string) (string, string, velocityColumnFlags, bool) {
	trimmed := strings.TrimSpace(def)
	if trimmed == "" || isTableConstraintDef(trimmed) {
		return def, "", velocityColumnFlags{}, false
	}
	tokens := tokenizeColumnDef(trimmed)
	if len(tokens) < 2 {
		return def, "", velocityColumnFlags{}, false
	}
	col := unquoteIdent(tokens[0])
	var flags velocityColumnFlags
	out := make([]string, 0, len(tokens))
	for i, token := range tokens {
		if i > 0 {
			switch normalizeDDLFlagToken(token) {
			case "index":
				flags.index = true
				continue
			case "fulltext":
				flags.fulltext = true
				continue
			case "value":
				flags.value = true
				continue
			}
		}
		out = append(out, token)
	}
	if !(flags.index || flags.fulltext || flags.value) {
		return def, col, flags, true
	}
	return leadingWhitespace(def) + strings.Join(out, " ") + trailingWhitespace(def), col, flags, true
}

func isTableConstraintDef(def string) bool {
	token := ""
	for _, r := range def {
		if unicode.IsSpace(r) || r == '(' {
			break
		}
		token += string(r)
	}
	switch strings.ToLower(unquoteIdent(token)) {
	case "primary", "unique", "index", "key", "foreign", "check", "constraint":
		return true
	default:
		return false
	}
}

func tokenizeColumnDef(def string) []string {
	var tokens []string
	for i := 0; i < len(def); {
		for i < len(def) && unicode.IsSpace(rune(def[i])) {
			i++
		}
		if i >= len(def) {
			break
		}
		start := i
		switch def[i] {
		case '`', '"', '\'':
			quote := def[i]
			i++
			for i < len(def) {
				if def[i] == quote {
					i++
					break
				}
				i++
			}
		case '(':
			depth := 1
			i++
			for i < len(def) && depth > 0 {
				switch def[i] {
				case '(':
					depth++
				case ')':
					depth--
				case '\'', '"', '`':
					quote := def[i]
					i++
					for i < len(def) && def[i] != quote {
						i++
					}
				}
				i++
			}
		default:
			for i < len(def) && !unicode.IsSpace(rune(def[i])) {
				i++
			}
		}
		tokens = append(tokens, def[start:i])
	}
	return tokens
}

func normalizeDDLFlagToken(token string) string {
	token = strings.Trim(strings.ToLower(token), "`\"'")
	token = strings.ReplaceAll(token, "-", "_")
	switch token {
	case "index", "hash", "hashindex", "hash_index":
		return "index"
	case "fulltext", "full_text":
		return "fulltext"
	case "valueindex", "value_index", "rangeindex", "range_index":
		return "value"
	default:
		return ""
	}
}

func mergeVelocityColumnFlags(a, b velocityColumnFlags) velocityColumnFlags {
	return velocityColumnFlags{
		index:    a.index || b.index,
		fulltext: a.fulltext || b.fulltext,
		value:    a.value || b.value,
	}
}

func splitTopLevelComma(s string) []string {
	var parts []string
	start := 0
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func matchingParen(s string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func unquoteIdent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '`' && last == '`') || (first == '"' && last == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func leadingWhitespace(s string) string {
	i := 0
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	return s[:i]
}

func trailingWhitespace(s string) string {
	i := len(s)
	for i > 0 && unicode.IsSpace(rune(s[i-1])) {
		i--
	}
	return s[i:]
}

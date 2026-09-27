package iam

import "strings"

// patternMatches reports whether value matches pattern, where pattern is
// either exactly "*" (matches anything), an exact literal match, or a
// prefix ending in "*" (e.g. "kv:*" matches "kv:Put" and "kv:Get" but not
// "object:Put", and "kv:" alone — no trailing "*" — matches ONLY the
// literal string "kv:", not "kv:Put"). This is intentionally the entire
// pattern language: no "?" single-char wildcard, no mid-string "*", no
// regex. A richer pattern language is a real feature request but also a
// real way to introduce a subtle over-permission bug; keep this small and
// exhaustively tested instead.
func patternMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return pattern == value
}

// anyPatternMatches reports whether value matches any pattern in
// patterns. An empty patterns slice matches nothing (not "anything") —
// callers building a statement with no actions/resources listed get a
// statement that can never fire, which is the safe failure direction for
// an access-control system.
func anyPatternMatches(patterns []string, value string) bool {
	for _, p := range patterns {
		if patternMatches(p, value) {
			return true
		}
	}
	return false
}

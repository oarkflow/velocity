package velocity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// KGExtractor extracts plain text from raw content based on media type.
type KGExtractor interface {
	Extract(content []byte, mediaType string) (string, error)
	Supports(mediaType string) bool
}

// DefaultExtractor handles text/plain, text/html, application/json, text/csv.
type DefaultExtractor struct{}

var (
	reScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTags   = regexp.MustCompile(`<[^>]+>`)
	reSpaces = regexp.MustCompile(`\s{2,}`)
)

func NewDefaultExtractor() *DefaultExtractor {
	return &DefaultExtractor{}
}

func (e *DefaultExtractor) Supports(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case "text/plain", "text/html", "application/json", "text/csv":
		return true
	}
	return false
}

func (e *DefaultExtractor) Extract(content []byte, mediaType string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("empty content")
	}

	switch normalizeMediaType(mediaType) {
	case "text/plain":
		return string(content), nil
	case "text/html":
		return extractHTML(content), nil
	case "application/json":
		return extractJSON(content)
	case "text/csv":
		return extractCSV(content), nil
	default:
		// Best effort: treat as plain text
		return string(content), nil
	}
}

func normalizeMediaType(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(mt))
	if idx := strings.Index(mt, ";"); idx >= 0 {
		mt = mt[:idx]
	}
	return strings.TrimSpace(mt)
}

func extractHTML(content []byte) string {
	s := string(content)
	s = reScript.ReplaceAllString(s, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reTags.ReplaceAllString(s, " ")
	// Decode common HTML entities
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func extractJSON(content []byte) (string, error) {
	var data any
	if err := json.Unmarshal(content, &data); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	var buf bytes.Buffer
	collectJSONStrings(data, &buf)
	return strings.TrimSpace(buf.String()), nil
}

func collectJSONStrings(v any, buf *bytes.Buffer) {
	switch val := v.(type) {
	case string:
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(val)
	case map[string]any:
		for _, mv := range val {
			collectJSONStrings(mv, buf)
		}
	case []any:
		for _, av := range val {
			collectJSONStrings(av, buf)
		}
	}
}

func extractCSV(content []byte) string {
	lines := strings.Split(string(content), "\n")
	var parts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			// Replace commas with spaces for readability
			line = strings.ReplaceAll(line, ",", " ")
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, " ")
}

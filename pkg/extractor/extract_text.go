package extractor

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Shared regexps
// ---------------------------------------------------------------------------

var (
	reScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTags   = regexp.MustCompile(`<[^>]+>`)
	reSpaces = regexp.MustCompile(`\s{2,}`)
)

// ---------------------------------------------------------------------------
// PlainTextExtractor
// ---------------------------------------------------------------------------

// PlainTextExtractor handles text/plain and text/markdown.
type PlainTextExtractor struct{}

func NewPlainTextExtractor() *PlainTextExtractor { return &PlainTextExtractor{} }

func (e *PlainTextExtractor) Supports(mt string) bool {
	return mt == "text/plain" || mt == "text/markdown"
}

func (e *PlainTextExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/plain: empty content")
	}
	return string(content), nil
}

// ---------------------------------------------------------------------------
// HTMLExtractor
// ---------------------------------------------------------------------------

// HTMLExtractor strips tags and decodes common HTML entities.
type HTMLExtractor struct{}

func NewHTMLExtractor() *HTMLExtractor { return &HTMLExtractor{} }

func (e *HTMLExtractor) Supports(mt string) bool {
	return mt == "text/html" || mt == "application/xhtml+xml"
}

func (e *HTMLExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/html: empty content")
	}
	return extractHTML(content), nil
}

func extractHTML(content []byte) string {
	s := string(content)
	s = reScript.ReplaceAllString(s, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reTags.ReplaceAllString(s, " ")
	s = htmlEntityDecode(s)
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var htmlEntities = map[string]string{
	"&amp;":    "&",
	"&lt;":     "<",
	"&gt;":     ">",
	"&quot;":   `"`,
	"&#39;":    "'",
	"&apos;":   "'",
	"&nbsp;":   " ",
	"&ndash;":  "-",
	"&mdash;":  "-",
	"&lsquo;":  "'",
	"&rsquo;":  "'",
	"&ldquo;":  `"`,
	"&rdquo;":  `"`,
	"&hellip;": "...",
}

func htmlEntityDecode(s string) string {
	for entity, replacement := range htmlEntities {
		s = strings.ReplaceAll(s, entity, replacement)
	}
	return s
}

// ---------------------------------------------------------------------------
// JSONExtractor
// ---------------------------------------------------------------------------

// JSONExtractor collects all string leaf values from a JSON document.
type JSONExtractor struct{}

func NewJSONExtractor() *JSONExtractor { return &JSONExtractor{} }

func (e *JSONExtractor) Supports(mt string) bool {
	return mt == "application/json" || mt == "text/json"
}

func (e *JSONExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/json: empty content")
	}
	return extractJSON(content)
}

func extractJSON(content []byte) (string, error) {
	var data any
	if err := json.Unmarshal(content, &data); err != nil {
		return "", fmt.Errorf("kg/json: invalid JSON: %w", err)
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

// ---------------------------------------------------------------------------
// CSVExtractor
// ---------------------------------------------------------------------------

// CSVExtractor converts CSV/TSV rows into whitespace-separated text.
// Uses encoding/csv so quoted fields with embedded commas are handled correctly.
type CSVExtractor struct{}

func NewCSVExtractor() *CSVExtractor { return &CSVExtractor{} }

func (e *CSVExtractor) Supports(mt string) bool {
	return mt == "text/csv" ||
		mt == "text/tab-separated-values" ||
		mt == "application/csv"
}

func (e *CSVExtractor) Extract(content []byte, mt string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/csv: empty content")
	}
	sep := ','
	if mt == "text/tab-separated-values" {
		sep = '\t'
	}
	r := csv.NewReader(bytes.NewReader(content))
	r.Comma = sep
	r.LazyQuotes = true
	r.FieldsPerRecord = -1 // allow variable field count

	records, err := r.ReadAll()
	if err != nil {
		// Fall back to naive split on parse error
		return naiveCSV(content, sep), nil
	}

	var parts []string
	for _, row := range records {
		for _, field := range row {
			field = strings.TrimSpace(field)
			if field != "" {
				parts = append(parts, field)
			}
		}
	}
	return strings.Join(parts, " "), nil
}

func naiveCSV(content []byte, sep rune) string {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	var parts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.ReplaceAll(line, string(sep), " ")
		parts = append(parts, line)
	}
	return reSpaces.ReplaceAllString(strings.Join(parts, " "), " ")
}

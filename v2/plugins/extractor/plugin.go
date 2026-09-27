// Package extractor implements Velocity v2's "extractor" plugin: content
// extraction from raw bytes, ported from v1's pkg/extractor.
//
// Formats: plain text, Markdown, HTML, JSON, CSV (pure stdlib), plus PDF
// (via the pure-Go github.com/oarkflow/pdf/reader — deliberately NOT v1's
// os/exec-shells-out-to-pdftotext approach, which only works if that
// external binary happens to be installed), DOCX and XLSX (ZIP+XML via
// stdlib archive/zip + encoding/xml), and .eml/RFC 822 email (stdlib
// net/mail + mime/multipart, including nested multipart, attachment
// listing, and quoted-printable/base64 content-transfer-encoding
// decoding).
package extractor

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin implements api.Plugin + api.ExtractorService. It is a stateless
// transform plugin — no storage dependency, Dependencies() returns nil.
type Plugin struct{}

func NewPlugin() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string           { return "extractor" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	return k.Registry().Provide("extractor", p)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return api.Health{Status: "ok"} }

var _ api.Plugin = (*Plugin)(nil)
var _ api.ExtractorService = (*Plugin)(nil)

func normalizeMediaType(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(mt))
	if idx := strings.Index(mt, ";"); idx >= 0 {
		mt = mt[:idx]
	}
	return strings.TrimSpace(mt)
}

func (p *Plugin) SupportedTypes(ctx context.Context) ([]string, error) {
	return []string{
		"text/plain", "text/markdown",
		"text/html", "application/xhtml+xml",
		"application/json",
		"text/csv",
		"application/pdf",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"message/rfc822",
	}, nil
}

func (p *Plugin) Extract(ctx context.Context, contentType string, r io.Reader) (api.ExtractedContent, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor: read: %w", err)
	}
	if len(content) == 0 {
		return api.ExtractedContent{}, fmt.Errorf("extractor: empty content")
	}

	switch normalizeMediaType(contentType) {
	case "text/plain", "text/markdown":
		return api.ExtractedContent{Text: string(content)}, nil

	case "text/html", "application/xhtml+xml":
		return api.ExtractedContent{Text: extractHTML(content)}, nil

	case "application/json":
		return extractJSON(content)

	case "text/csv":
		return extractCSV(content)

	case "application/pdf":
		return extractPDF(content)

	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return extractDOCX(content)

	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return extractXLSX(content)

	case "message/rfc822":
		return extractEML(content)

	default:
		return api.ExtractedContent{}, fmt.Errorf("extractor: unsupported media type %q", contentType)
	}
}

// --- HTML ---

var (
	reScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTags   = regexp.MustCompile(`<[^>]+>`)
	reSpaces = regexp.MustCompile(`\s{2,}`)
)

var htmlEntities = map[string]string{
	"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": `"`,
	"&#39;": "'", "&apos;": "'", "&nbsp;": " ",
	"&ldquo;": `"`, "&rdquo;": `"`, "&lsquo;": "'", "&rsquo;": "'",
	"&mdash;": "-", "&ndash;": "-", "&hellip;": "...",
}

func htmlEntityDecode(s string) string {
	for entity, repl := range htmlEntities {
		s = strings.ReplaceAll(s, entity, repl)
	}
	return s
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

// --- JSON ---

func extractJSON(content []byte) (api.ExtractedContent, error) {
	var v any
	if err := json.Unmarshal(content, &v); err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/json: %w", err)
	}
	var sb strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			sb.WriteString(t)
			sb.WriteByte(' ')
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		case float64, bool, nil:
			// numbers/bools/null contribute no extractable text
		}
	}
	walk(v)
	meta := map[string]any{}
	if m, ok := v.(map[string]any); ok {
		meta = m
	}
	return api.ExtractedContent{Text: strings.TrimSpace(sb.String()), Metadata: meta}, nil
}

// --- CSV ---

func extractCSV(content []byte) (api.ExtractedContent, error) {
	rd := csv.NewReader(bytes.NewReader(content))
	rows, err := rd.ReadAll()
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/csv: %w", err)
	}
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(strings.Join(row, " "))
		sb.WriteByte('\n')
	}
	meta := map[string]any{"rows": len(rows)}
	if len(rows) > 0 {
		meta["columns"] = len(rows[0])
	}
	return api.ExtractedContent{Text: strings.TrimSpace(sb.String()), Metadata: meta}, nil
}

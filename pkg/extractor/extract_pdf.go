package extractor

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// PDFExtractor
// ---------------------------------------------------------------------------

// PDFExtractor extracts text from PDF files using pdftotext (poppler-utils).
//
// Strategy (in order):
//  1. pdftotext -layout   – preserves column layout; best for structured docs
//  2. pdftotext           – plain mode; better for flowing prose
//  3. pdftotext -raw      – raw content stream order; last resort
//  4. extractPrintableText – pure Go printable-byte scrape if pdftotext absent
//
// The extractor writes the PDF to a temp file because pdftotext requires a
// file path, not stdin.  The temp file is removed after extraction.
//
// Configuration:
//
//	PDFExtractorConfig.Timeout controls the subprocess timeout (default 30s).
//	PDFExtractorConfig.MaxBytes caps the returned text (0 = unlimited).
type PDFExtractorConfig struct {
	// Timeout for each pdftotext invocation. Zero means 30 s.
	Timeout time.Duration
	// MaxBytes truncates the result to this many bytes. Zero means unlimited.
	MaxBytes int
	// PdftotextPath overrides the path to pdftotext. Zero value = PATH lookup.
	PdftotextPath string
}

type PDFExtractor struct {
	cfg PDFExtractorConfig
}

func NewPDFExtractor() *PDFExtractor {
	return &PDFExtractor{cfg: PDFExtractorConfig{Timeout: 30 * time.Second}}
}

func NewPDFExtractorWithConfig(cfg PDFExtractorConfig) *PDFExtractor {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &PDFExtractor{cfg: cfg}
}

func (e *PDFExtractor) Supports(mt string) bool {
	return mt == "application/pdf"
}

func (e *PDFExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/pdf: empty content")
	}

	// Verify it looks like a PDF.
	if !bytes.HasPrefix(content, []byte("%PDF")) {
		return "", fmt.Errorf("kg/pdf: content does not start with PDF magic bytes")
	}

	// Locate pdftotext.
	bin, err := e.findBinary()
	if err != nil {
		if text := extractPDFContentStreamText(content); strings.TrimSpace(text) != "" {
			return e.postProcess(text), nil
		}
		return extractPrintableText(content), nil
	}

	// Write to temp file.
	tmp, err := os.CreateTemp("", "kg-pdf-*.pdf")
	if err != nil {
		return "", fmt.Errorf("kg/pdf: cannot create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return "", fmt.Errorf("kg/pdf: cannot write temp file: %w", err)
	}
	tmp.Close()

	// Try extraction strategies in order.
	strategies := [][]string{
		{"-layout", tmp.Name(), "-"},
		{tmp.Name(), "-"},
		{"-raw", tmp.Name(), "-"},
	}

	for _, args := range strategies {
		text, err := e.runPdftotext(bin, args)
		if err == nil && strings.TrimSpace(text) != "" {
			return e.postProcess(text), nil
		}
	}

	if text := extractPDFContentStreamText(content); strings.TrimSpace(text) != "" {
		return e.postProcess(text), nil
	}

	return extractPrintableText(content), nil
}

func (e *PDFExtractor) findBinary() (string, error) {
	if e.cfg.PdftotextPath != "" {
		if _, err := os.Stat(e.cfg.PdftotextPath); err != nil {
			return "", fmt.Errorf("kg/pdf: pdftotext not found at %s: %w", e.cfg.PdftotextPath, err)
		}
		return e.cfg.PdftotextPath, nil
	}
	p, err := exec.LookPath("pdftotext")
	if err != nil {
		return "", fmt.Errorf("kg/pdf: pdftotext not in PATH: %w", err)
	}
	return p, nil
}

func extractPDFContentStreamText(content []byte) string {
	var out strings.Builder
	searchFrom := 0
	for {
		streamIdx := bytes.Index(content[searchFrom:], []byte("stream"))
		if streamIdx < 0 {
			break
		}
		streamIdx += searchFrom
		dataStart := streamIdx + len("stream")
		if dataStart < len(content) && content[dataStart] == '\r' {
			dataStart++
		}
		if dataStart < len(content) && content[dataStart] == '\n' {
			dataStart++
		}
		endRel := bytes.Index(content[dataStart:], []byte("endstream"))
		if endRel < 0 {
			break
		}
		dataEnd := dataStart + endRel
		raw := bytes.TrimSpace(content[dataStart:dataEnd])
		dictStart := streamDictStart(content, streamIdx)
		dict := content[dictStart:streamIdx]
		decoded := decodePDFStream(raw, dict)
		text := extractPDFTextOperators(decoded)
		if text != "" {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.WriteString(text)
		}
		searchFrom = dataEnd + len("endstream")
	}
	return strings.TrimSpace(reSpaces.ReplaceAllString(out.String(), " "))
}

func streamDictStart(content []byte, streamIdx int) int {
	start := streamIdx - 2048
	if start < 0 {
		start = 0
	}
	if rel := bytes.LastIndex(content[start:streamIdx], []byte("<<")); rel >= 0 {
		return start + rel
	}
	return start
}

func decodePDFStream(raw, dict []byte) []byte {
	data := raw
	if bytes.Contains(dict, []byte("ASCII85Decode")) || bytes.Contains(dict, []byte("/A85")) {
		src := bytes.TrimSpace(data)
		src = bytes.TrimPrefix(src, []byte("<~"))
		src = bytes.TrimSuffix(src, []byte("~>"))
		dst := make([]byte, len(src)*4/5+8)
		n, _, err := ascii85.Decode(dst, src, true)
		if err == nil {
			data = dst[:n]
		}
	}
	if bytes.Contains(dict, []byte("FlateDecode")) || bytes.Contains(dict, []byte("/Fl")) {
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err == nil {
			defer r.Close()
			if decoded, err := io.ReadAll(r); err == nil {
				data = decoded
			}
		}
	}
	return data
}

var pdfTextOpPattern = regexp.MustCompile(`(?s)(\((?:\\.|[^\\()])*\)|\[(?:.|\n|\r)*?\])\s*T[Jj]`)

func extractPDFTextOperators(stream []byte) string {
	matches := pdfTextOpPattern.FindAllSubmatch(stream, -1)
	if len(matches) == 0 {
		return ""
	}
	var out strings.Builder
	for _, m := range matches {
		operand := bytes.TrimSpace(m[1])
		if len(operand) == 0 {
			continue
		}
		if operand[0] == '[' {
			for _, lit := range extractPDFLiteralStrings(operand) {
				writePDFText(&out, lit)
			}
			continue
		}
		writePDFText(&out, decodePDFLiteralString(operand))
	}
	return strings.TrimSpace(out.String())
}

func extractPDFLiteralStrings(data []byte) []string {
	var values []string
	for i := 0; i < len(data); i++ {
		if data[i] != '(' {
			continue
		}
		start := i
		depth := 0
		escaped := false
		for ; i < len(data); i++ {
			c := data[i]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					values = append(values, decodePDFLiteralString(data[start:i+1]))
					break
				}
			}
		}
	}
	return values
}

func writePDFText(out *strings.Builder, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	if out.Len() > 0 {
		out.WriteByte(' ')
	}
	out.WriteString(text)
}

func decodePDFLiteralString(lit []byte) string {
	lit = bytes.TrimSpace(lit)
	if len(lit) >= 2 && lit[0] == '(' && lit[len(lit)-1] == ')' {
		lit = lit[1 : len(lit)-1]
	}
	var out strings.Builder
	for i := 0; i < len(lit); i++ {
		c := lit[i]
		if c != '\\' || i+1 >= len(lit) {
			out.WriteByte(c)
			continue
		}
		i++
		switch lit[i] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b', 'f':
		case '(', ')', '\\':
			out.WriteByte(lit[i])
		case '\n':
		case '\r':
			if i+1 < len(lit) && lit[i+1] == '\n' {
				i++
			}
		default:
			if lit[i] >= '0' && lit[i] <= '7' {
				val := int(lit[i] - '0')
				for j := 0; j < 2 && i+1 < len(lit) && lit[i+1] >= '0' && lit[i+1] <= '7'; j++ {
					i++
					val = val*8 + int(lit[i]-'0')
				}
				out.WriteByte(byte(val))
			} else {
				out.WriteByte(lit[i])
			}
		}
	}
	return out.String()
}

func (e *PDFExtractor) runPdftotext(bin string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kg/pdf: pdftotext failed: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.String(), nil
}

func (e *PDFExtractor) postProcess(text string) string {
	// Normalise line endings.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// Remove form-feed characters (page separators pdftotext emits).
	text = strings.ReplaceAll(text, "\f", "\n\n")

	// Collapse runs of blank lines to at most two.
	reBlankLines := strings.NewReplacer("\n\n\n\n", "\n\n", "\n\n\n", "\n\n")
	for strings.Contains(text, "\n\n\n") {
		text = reBlankLines.Replace(text)
	}

	if e.cfg.MaxBytes > 0 && len(text) > e.cfg.MaxBytes {
		text = text[:e.cfg.MaxBytes]
	}
	return strings.TrimSpace(text)
}

// ---------------------------------------------------------------------------
// PrintableTextExtractor
// ---------------------------------------------------------------------------

// PrintableTextExtractor is a last-resort extractor that scans content for
// printable ASCII bytes. Useful for unknown binary formats.
type PrintableTextExtractor struct {
	// MinRunLength is the minimum consecutive printable-byte run to include.
	// Zero defaults to 4.
	MinRunLength int
}

func NewPrintableTextExtractor() *PrintableTextExtractor {
	return &PrintableTextExtractor{MinRunLength: 4}
}

func (e *PrintableTextExtractor) Supports(mt string) bool {
	// Matches any unrecognised type.
	return true
}

func (e *PrintableTextExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/printable: empty content")
	}
	return extractPrintableText(content), nil
}

// extractPrintableText scans byte-by-byte and collects printable ASCII runs.
func extractPrintableText(content []byte) string {
	var b strings.Builder
	runLen := 0
	var run strings.Builder

	flush := func() {
		if runLen >= 4 {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(run.String())
		}
		run.Reset()
		runLen = 0
	}

	for _, c := range content {
		if (c >= 32 && c <= 126) || c == '\t' || c == '\n' || c == '\r' {
			if c == '\t' || c == '\n' || c == '\r' {
				c = ' '
			}
			run.WriteByte(c)
			runLen++
		} else {
			flush()
		}
	}
	flush()

	return strings.TrimSpace(reSpaces.ReplaceAllString(b.String(), " "))
}

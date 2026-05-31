package extractor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
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
		// Fall back to printable-byte scrape.
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

	// Last resort: printable-byte scrape.
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

package extractor

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// --- DOCX ---

// buildMinimalDOCX constructs a real, valid .docx (a ZIP archive
// containing word/document.xml) with the given paragraph texts, exactly
// as Microsoft Word would lay it out at the level extractDOCX reads.
func buildMinimalDOCX(t *testing.T, paragraphs ...string) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sb.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, p := range paragraphs {
		sb.WriteString(`<w:p><w:r><w:t xml:space="preserve">`)
		sb.WriteString(p)
		sb.WriteString(`</w:t></w:r></w:p>`)
	}
	sb.WriteString(`</w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := f.Write([]byte(sb.String())); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractDOCX(t *testing.T) {
	docx := buildMinimalDOCX(t, "Hello from a real docx.", "Second paragraph here.")
	p := NewPlugin()
	out, err := p.Extract(context.Background(),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		bytes.NewReader(docx))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "Hello from a real docx.") || !strings.Contains(out.Text, "Second paragraph here.") {
		t.Fatalf("Text = %q, missing expected paragraph content", out.Text)
	}
	if out.Metadata["paragraphs"] != 2 {
		t.Fatalf("Metadata[paragraphs] = %v, want 2", out.Metadata["paragraphs"])
	}
}

func TestExtractDOCX_RejectsNonZip(t *testing.T) {
	p := NewPlugin()
	_, err := p.Extract(context.Background(),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		strings.NewReader("not a zip file"))
	if err == nil {
		t.Fatal("expected an error for a non-zip .docx payload")
	}
}

// --- EML ---

func TestExtractEML_PlainText(t *testing.T) {
	raw := "From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Test message\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"This is the plain text body.\r\n"

	p := NewPlugin()
	out, err := p.Extract(context.Background(), "message/rfc822", strings.NewReader(raw))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "This is the plain text body.") {
		t.Fatalf("Text = %q, missing body", out.Text)
	}
	if out.Metadata["subject"] != "Test message" {
		t.Fatalf("Metadata[subject] = %v, want %q", out.Metadata["subject"], "Test message")
	}
	if out.Metadata["from"] != "alice@example.com" {
		t.Fatalf("Metadata[from] = %v, want alice@example.com", out.Metadata["from"])
	}
}

func TestExtractEML_Multipart(t *testing.T) {
	boundary := "BOUNDARY123"
	raw := fmt.Sprintf(
		"From: carol@example.com\r\n"+
			"Subject: Multipart test\r\n"+
			"Content-Type: multipart/alternative; boundary=%s\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: text/plain\r\n"+
			"\r\n"+
			"Plain part text.\r\n"+
			"--%s\r\n"+
			"Content-Type: text/html\r\n"+
			"\r\n"+
			"<html><body><p>HTML part text.</p></body></html>\r\n"+
			"--%s--\r\n",
		boundary, boundary, boundary, boundary,
	)

	p := NewPlugin()
	out, err := p.Extract(context.Background(), "message/rfc822", strings.NewReader(raw))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "Plain part text.") {
		t.Fatalf("Text = %q, expected the text/plain part to be preferred", out.Text)
	}
	if out.Metadata["subject"] != "Multipart test" {
		t.Fatalf("Metadata[subject] = %v, want %q", out.Metadata["subject"], "Multipart test")
	}
}

func TestExtractEML_MultipartHTMLFallback(t *testing.T) {
	boundary := "BOUNDARY456"
	raw := fmt.Sprintf(
		"Subject: HTML only\r\n"+
			"Content-Type: multipart/alternative; boundary=%s\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: text/html\r\n"+
			"\r\n"+
			"<html><body><p>Only HTML here.</p></body></html>\r\n"+
			"--%s--\r\n",
		boundary, boundary, boundary,
	)

	p := NewPlugin()
	out, err := p.Extract(context.Background(), "message/rfc822", strings.NewReader(raw))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "Only HTML here.") {
		t.Fatalf("Text = %q, expected HTML fallback to strip tags and keep text", out.Text)
	}
	if strings.Contains(out.Text, "<p>") {
		t.Fatalf("Text = %q, expected HTML tags to be stripped", out.Text)
	}
}

// --- PDF ---

// buildMinimalPDF constructs a small but real, structurally valid PDF
// (correct xref byte offsets computed as it's written) containing a
// single page whose content stream draws the given text — enough for a
// real PDF parser (not a mock) to extract it back out.
func buildMinimalPDF(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	offsets := make([]int, 0, 6)

	write := func(s string) {
		buf.WriteString(s)
	}
	startObj := func() {
		offsets = append(offsets, buf.Len())
	}

	write("%PDF-1.4\n")

	startObj() // 1: Catalog
	write("1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n")

	startObj() // 2: Pages
	write("2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n")

	startObj() // 3: Page
	write("3 0 obj<</Type/Page/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/MediaBox[0 0 200 200]/Contents 5 0 R>>endobj\n")

	startObj() // 4: Font
	write("4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n")

	content := fmt.Sprintf("BT /F1 24 Tf 10 100 Td (%s) Tj ET", text)
	startObj() // 5: Contents
	write(fmt.Sprintf("5 0 obj<</Length %d>>\nstream\n%s\nendstream\nendobj\n", len(content), content))

	xrefStart := buf.Len()
	write("xref\n")
	write(fmt.Sprintf("0 %d\n", len(offsets)+1))
	write("0000000000 65535 f \n")
	for _, off := range offsets {
		write(fmt.Sprintf("%010d 00000 n \n", off))
	}
	write("trailer<</Size 6/Root 1 0 R>>\n")
	write(fmt.Sprintf("startxref\n%d\n", xrefStart))
	write("%%EOF")

	return buf.Bytes()
}

func TestExtractPDF(t *testing.T) {
	pdfBytes := buildMinimalPDF(t, "Hello PDF")
	p := NewPlugin()
	out, err := p.Extract(context.Background(), "application/pdf", bytes.NewReader(pdfBytes))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "Hello PDF") {
		t.Fatalf("Text = %q, want it to contain %q", out.Text, "Hello PDF")
	}
	if out.Metadata["pages"] != 1 {
		t.Fatalf("Metadata[pages] = %v, want 1", out.Metadata["pages"])
	}
}

func TestExtractPDF_RejectsGarbage(t *testing.T) {
	p := NewPlugin()
	_, err := p.Extract(context.Background(), "application/pdf", strings.NewReader("not a pdf at all"))
	if err == nil {
		t.Fatal("expected an error for a non-PDF payload")
	}
}

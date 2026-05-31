package kg

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestDefaultExtractor_PlainText(t *testing.T) {
	ext := NewDefaultExtractor()
	text, err := ext.Extract([]byte("Hello world"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if text != "Hello world" {
		t.Fatalf("expected 'Hello world', got %q", text)
	}
}

func TestDefaultExtractor_HTML(t *testing.T) {
	ext := NewDefaultExtractor()
	html := `<html><head><script>var x=1;</script><style>.a{color:red}</style></head>
	<body><h1>Title</h1><p>Hello &amp; world</p></body></html>`
	text, err := ext.Extract([]byte(html), "text/html")
	if err != nil {
		t.Fatal(err)
	}
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if strings.Contains(text, "<") || strings.Contains(text, "var x") || strings.Contains(text, "color:red") {
		t.Fatalf("HTML not properly stripped: %q", text)
	}
	if !strings.Contains(text, "Hello & world") {
		t.Fatalf("entities not decoded: %q", text)
	}
}

func TestDefaultExtractor_JSON(t *testing.T) {
	ext := NewDefaultExtractor()
	j := `{"name":"Alice","age":30,"address":{"city":"NYC"}}`
	text, err := ext.Extract([]byte(j), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Alice") || !strings.Contains(text, "NYC") {
		t.Fatalf("JSON strings not extracted: %q", text)
	}
}

func TestDefaultExtractor_Empty(t *testing.T) {
	ext := NewDefaultExtractor()
	_, err := ext.Extract([]byte{}, "text/plain")
	if err == nil {
		t.Fatal("expected error for empty content")
	}
}

func TestDefaultExtractor_Supports(t *testing.T) {
	ext := NewDefaultExtractor()
	if !ext.Supports("text/plain") {
		t.Fatal("should support text/plain")
	}
	if !ext.Supports("text/html; charset=utf-8") {
		t.Fatal("should support text/html with params")
	}
	if !ext.Supports("application/pdf") {
		t.Fatal("should support PDF fallback")
	}
}

func TestDefaultExtractor_EmailAndBinaryFallbacks(t *testing.T) {
	ext := NewDefaultExtractor()
	email := "From: alice@example.test\r\nTo: bob@example.test\r\nSubject: Contract CASE-12345\r\nIgnored: nope\r\n\r\nPlease review the attached policy."
	text, err := ext.Extract([]byte(email), "message/rfc822")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Subject: Contract CASE-12345") || strings.Contains(text, "Ignored: nope") || !strings.Contains(text, "attached policy") {
		t.Fatalf("unexpected email extraction: %q", text)
	}

	pdfText, err := ext.Extract([]byte("%PDF-1.7\x00 hidden CASE-77777 text\x00%%EOF"), "application/pdf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pdfText, "CASE-77777") {
		t.Fatalf("expected printable PDF fallback text: %q", pdfText)
	}
}

func TestDefaultExtractor_UsesRichOfficeExtractor(t *testing.T) {
	ext := NewDefaultExtractor()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Accurate DOCX CASE-90909</w:t></w:r></w:p></w:body></w:document>`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	text, err := ext.Extract(buf.Bytes(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Accurate DOCX CASE-90909") {
		t.Fatalf("expected docx text from rich extractor: %q", text)
	}
}

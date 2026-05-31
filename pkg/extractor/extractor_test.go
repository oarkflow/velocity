package extractor_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	kg "github.com/oarkflow/velocity/pkg/extractor"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustExtract(t *testing.T, content []byte, mt string) string {
	t.Helper()
	text, err := kg.Extract(content, mt)
	if err != nil {
		t.Fatalf("Extract(%q) error: %v", mt, err)
	}
	return text
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q to contain %q", haystack, needle)
	}
}

// ---------------------------------------------------------------------------
// PlainText
// ---------------------------------------------------------------------------

func TestPlainText(t *testing.T) {
	out := mustExtract(t, []byte("hello world"), "text/plain")
	assertContains(t, out, "hello world")
}

func TestPlainTextWithParams(t *testing.T) {
	out := mustExtract(t, []byte("hello"), "text/plain; charset=utf-8")
	assertContains(t, out, "hello")
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

func TestHTML(t *testing.T) {
	html := `<html><head><style>body{}</style></head><body><h1>Title</h1><p>Hello &amp; world</p><script>alert(1)</script></body></html>`
	out := mustExtract(t, []byte(html), "text/html")
	assertContains(t, out, "Title")
	assertContains(t, out, "Hello & world")
	if strings.Contains(out, "alert") {
		t.Error("script content should be stripped")
	}
	if strings.Contains(out, "body{}") {
		t.Error("style content should be stripped")
	}
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

func TestJSON(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"title": "Gopher",
		"tags":  []string{"go", "programming"},
		"meta":  map[string]any{"author": "Alice"},
	})
	out := mustExtract(t, data, "application/json")
	assertContains(t, out, "Gopher")
	assertContains(t, out, "go")
	assertContains(t, out, "Alice")
}

func TestJSONInvalid(t *testing.T) {
	_, err := kg.Extract([]byte("{bad json"), "application/json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

func TestCSV(t *testing.T) {
	csv := "name,age,city\nAlice,30,\"New York\"\nBob,25,London\n"
	out := mustExtract(t, []byte(csv), "text/csv")
	assertContains(t, out, "Alice")
	assertContains(t, out, "New York")
	assertContains(t, out, "London")
}

func TestTSV(t *testing.T) {
	tsv := "name\tage\nAlice\t30\n"
	out := mustExtract(t, []byte(tsv), "text/tab-separated-values")
	assertContains(t, out, "Alice")
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

func TestEmail(t *testing.T) {
	email := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nThis is the body.\r\n"
	out := mustExtract(t, []byte(email), "message/rfc822")
	assertContains(t, out, "alice@example.com")
	assertContains(t, out, "Hello")
	assertContains(t, out, "This is the body")
}

func TestEmailEncodedSubjectAndBase64Body(t *testing.T) {
	email := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: =?UTF-8?B?Q2Fzw6kgVXBkYXRl?=\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nQm9keSBDQVNFLTEyMzQ1\r\n"
	out := mustExtract(t, []byte(email), "message/rfc822")
	assertContains(t, out, "Casé Update")
	assertContains(t, out, "Body CASE-12345")
}

// ---------------------------------------------------------------------------
// DOCX (minimal synthetic)
// ---------------------------------------------------------------------------

func buildDocx(t *testing.T, bodyXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addZipFile(t, zw, "word/document.xml", []byte(bodyXML))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addZipFile(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestDocx(t *testing.T) {
	docXML := `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello from docx</w:t></w:r></w:p></w:body></w:document>`
	content := buildDocx(t, docXML)
	out := mustExtract(t, content, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	assertContains(t, out, "Hello from docx")
}

// ---------------------------------------------------------------------------
// XLSX
// ---------------------------------------------------------------------------

func TestXlsx(t *testing.T) {
	sharedStringsXML := `<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>Revenue</t></si><si><t>42000</t></si></sst>`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addZipFile(t, zw, "xl/sharedStrings.xml", []byte(sharedStringsXML))
	zw.Close()
	out := mustExtract(t, buf.Bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	assertContains(t, out, "Revenue")
	assertContains(t, out, "42000")
}

// ---------------------------------------------------------------------------
// PPTX
// ---------------------------------------------------------------------------

func TestPptx(t *testing.T) {
	slideXML := `<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Slide Title</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addZipFile(t, zw, "ppt/slides/slide1.xml", []byte(slideXML))
	zw.Close()
	out := mustExtract(t, buf.Bytes(), "application/vnd.openxmlformats-officedocument.presentationml.presentation")
	assertContains(t, out, "Slide Title")
}

// ---------------------------------------------------------------------------
// Unsupported type error
// ---------------------------------------------------------------------------

func TestUnsupported(t *testing.T) {
	// PrintableTextExtractor catches everything, so test the registry directly.
	r := kg.NewRegistry()
	r.Register(kg.NewPlainTextExtractor())
	_, err := r.Extract([]byte("data"), "application/octet-stream")
	if err == nil {
		t.Error("expected error for unsupported type with minimal registry")
	}
}

// ---------------------------------------------------------------------------
// Empty content
// ---------------------------------------------------------------------------

func TestEmptyContent(t *testing.T) {
	for _, mt := range []string{"text/plain", "text/html", "application/json", "text/csv"} {
		_, err := kg.Extract([]byte{}, mt)
		if err == nil {
			t.Errorf("expected error for empty content with %s", mt)
		}
	}
}

// ---------------------------------------------------------------------------
// NormalizeMediaType
// ---------------------------------------------------------------------------

func TestNormalizeMediaType(t *testing.T) {
	cases := map[string]string{
		"text/HTML; charset=utf-8": "text/html",
		"  Application/JSON  ":     "application/json",
		"text/plain":               "text/plain",
	}
	for input, want := range cases {
		got := kg.NormalizeMediaType(input)
		if got != want {
			t.Errorf("NormalizeMediaType(%q) = %q, want %q", input, got, want)
		}
	}
}

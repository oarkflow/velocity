package velocity

import (
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
	if ext.Supports("application/pdf") {
		t.Fatal("should not support PDF")
	}
}

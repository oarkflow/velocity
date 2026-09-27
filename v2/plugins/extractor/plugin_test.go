package extractor

import (
	"context"
	"strings"
	"testing"
)

func TestExtractPlainText(t *testing.T) {
	p := NewPlugin()
	out, err := p.Extract(context.Background(), "text/plain", strings.NewReader("hello world"))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if out.Text != "hello world" {
		t.Fatalf("got %q", out.Text)
	}
}

func TestExtractHTML(t *testing.T) {
	p := NewPlugin()
	html := `<html><head><style>body{color:red}</style></head><body><script>evil()</script><h1>Title</h1><p>Hello &amp; welcome</p></body></html>`
	out, err := p.Extract(context.Background(), "text/html; charset=utf-8", strings.NewReader(html))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if strings.Contains(out.Text, "evil") || strings.Contains(out.Text, "color:red") {
		t.Fatalf("script/style leaked into extracted text: %q", out.Text)
	}
	if !strings.Contains(out.Text, "Title") || !strings.Contains(out.Text, "Hello & welcome") {
		t.Fatalf("expected extracted text to contain Title and decoded entity, got %q", out.Text)
	}
}

func TestExtractJSON(t *testing.T) {
	p := NewPlugin()
	out, err := p.Extract(context.Background(), "application/json", strings.NewReader(`{"title":"Gopher","tags":["go","programming"],"meta":{"author":"Alice"}}`))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"Gopher", "go", "programming", "Alice"} {
		if !strings.Contains(out.Text, want) {
			t.Fatalf("expected extracted text to contain %q, got %q", want, out.Text)
		}
	}
	if out.Metadata["title"] != "Gopher" {
		t.Fatalf("expected metadata to include original JSON object, got %#v", out.Metadata)
	}
}

func TestExtractCSV(t *testing.T) {
	p := NewPlugin()
	out, err := p.Extract(context.Background(), "text/csv", strings.NewReader("name,age\nAlice,30\nBob,25\n"))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(out.Text, "Alice") || !strings.Contains(out.Text, "Bob") {
		t.Fatalf("expected extracted text to contain row data, got %q", out.Text)
	}
	if out.Metadata["rows"] != 3 || out.Metadata["columns"] != 2 {
		t.Fatalf("expected metadata rows=3 columns=2, got %#v", out.Metadata)
	}
}

func TestExtractUnsupportedType(t *testing.T) {
	p := NewPlugin()
	if _, err := p.Extract(context.Background(), "video/mp4", strings.NewReader("not a real mp4")); err == nil {
		t.Fatal("expected an error for unsupported media type video/mp4")
	}
}

func TestSupportedTypes(t *testing.T) {
	p := NewPlugin()
	types, err := p.SupportedTypes(context.Background())
	if err != nil {
		t.Fatalf("supported types: %v", err)
	}
	if len(types) == 0 {
		t.Fatal("expected a non-empty supported-types list")
	}
}

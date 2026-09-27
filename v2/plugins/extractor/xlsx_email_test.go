package extractor

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"mime/quotedprintable"
	"strings"
	"testing"
)

// --- XLSX ---

// buildMinimalXLSX constructs a real, valid .xlsx (a ZIP archive
// containing xl/sharedStrings.xml + xl/worksheets/sheet1.xml) with a
// small 3-row, 3-column sheet: row 1 is a shared-string header, row 2 mixes
// a shared string with a literal number, row 3 is all shared strings —
// exercising both the t="s" (shared string) and default/numeric cell
// paths real spreadsheet software emits.
func buildMinimalXLSX(t *testing.T) []byte {
	t.Helper()

	sharedStrings := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="5" uniqueCount="5">` +
		`<si><t>Name</t></si>` +
		`<si><t>Age</t></si>` +
		`<si><t>City</t></si>` +
		`<si><t>alice</t></si>` +
		`<si><t>NYC</t></si>` +
		`</sst>`

	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row>` +
		`<row r="2"><c r="A2" t="s"><v>3</v></c><c r="B2"><v>30</v></c><c r="C2" t="s"><v>4</v></c></row>` +
		`</sheetData></worksheet>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"xl/sharedStrings.xml":     sharedStrings,
		"xl/worksheets/sheet1.xml": sheet,
	} {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractXLSX(t *testing.T) {
	content := buildMinimalXLSX(t)
	p := NewPlugin()
	got, err := p.Extract(context.Background(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	wantText := "Name\tAge\tCity\nalice\t30\tNYC"
	if got.Text != wantText {
		t.Fatalf("Text = %q, want %q", got.Text, wantText)
	}
	if got.Metadata["sheets"] != 1 {
		t.Fatalf("Metadata[sheets] = %v, want 1", got.Metadata["sheets"])
	}
	if got.Metadata["rows"] != 2 {
		t.Fatalf("Metadata[rows] = %v, want 2", got.Metadata["rows"])
	}
	if got.Metadata["columns"] != 3 {
		t.Fatalf("Metadata[columns] = %v, want 3", got.Metadata["columns"])
	}
}

func TestExtractXLSX_RejectsNonZip(t *testing.T) {
	p := NewPlugin()
	_, err := p.Extract(context.Background(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", strings.NewReader("not a zip"))
	if err == nil {
		t.Fatal("expected an error for garbage input, got nil")
	}
}

// --- Email: nested multipart, attachments, transfer-encoding ---

// buildNestedMultipartEML constructs a real multipart/mixed message
// containing a nested multipart/alternative body (plain text encoded
// quoted-printable, HTML encoded base64) plus one attachment part, laid
// out exactly as a real mail client would produce it.
func buildNestedMultipartEML(t *testing.T) []byte {
	t.Helper()

	// The é (multi-byte UTF-8) forces the real quoted-printable ENCODER to
	// emit actual "=XX" escapes (it must escape any non-ASCII byte) — this
	// is what proves the extractor's DECODER round-trips real encoded
	// content correctly, not just passes through already-plain text.
	var plainQP bytes.Buffer
	qw := quotedprintable.NewWriter(&plainQP)
	if _, err := qw.Write([]byte("Caf\xc3\xa9 costs a lot and needs proper decoding.")); err != nil {
		t.Fatalf("qp write: %v", err)
	}
	if err := qw.Close(); err != nil {
		t.Fatalf("qp close: %v", err)
	}

	htmlB64 := base64Encode(t, []byte("<html><body><p>Hello <b>world</b></p></body></html>"))
	attachmentB64 := base64Encode(t, []byte("PDF-BINARY-CONTENT-PLACEHOLDER"))

	msg := "" +
		"Subject: Nested multipart test\r\n" +
		"From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Content-Type: multipart/mixed; boundary=\"outer-boundary\"\r\n" +
		"\r\n" +
		"--outer-boundary\r\n" +
		"Content-Type: multipart/alternative; boundary=\"inner-boundary\"\r\n" +
		"\r\n" +
		"--inner-boundary\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		plainQP.String() + "\r\n" +
		"--inner-boundary\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		htmlB64 + "\r\n" +
		"--inner-boundary--\r\n" +
		"--outer-boundary\r\n" +
		"Content-Type: application/pdf\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n" +
		"\r\n" +
		attachmentB64 + "\r\n" +
		"--outer-boundary--\r\n"

	return []byte(msg)
}

func base64Encode(t *testing.T, data []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(data)
}

func TestExtractEML_NestedMultipartWithAttachmentAndEncodings(t *testing.T) {
	content := buildNestedMultipartEML(t)
	p := NewPlugin()
	got, err := p.Extract(context.Background(), "message/rfc822", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// The plain-text part (preferred over HTML) must be correctly
	// quoted-printable DECODED, not left as raw "=C3=A9"-style escapes.
	wantText := "Café costs a lot and needs proper decoding."
	if got.Text != wantText {
		t.Fatalf("Text = %q, want %q (quoted-printable decoding failed)", got.Text, wantText)
	}

	attachments, ok := got.Metadata["attachments"].([]string)
	if !ok || len(attachments) != 1 || attachments[0] != "invoice.pdf" {
		t.Fatalf("Metadata[attachments] = %v, want [\"invoice.pdf\"]", got.Metadata["attachments"])
	}
}

func TestExtractEML_Base64PlainBody(t *testing.T) {
	body := base64Encode(t, []byte("This is the real decoded plain body."))
	msg := "" +
		"Subject: Base64 body test\r\n" +
		"From: sender@example.com\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		body + "\r\n"

	p := NewPlugin()
	got, err := p.Extract(context.Background(), "message/rfc822", bytes.NewReader([]byte(msg)))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want := "This is the real decoded plain body."
	if got.Text != want {
		t.Fatalf("Text = %q, want %q (base64 decoding failed)", got.Text, want)
	}
}

func TestExtractEML_NestedMultipartWithoutEncodingStillWorks(t *testing.T) {
	// Regression guard: a plain (non-encoded) nested multipart/alternative
	// inside multipart/mixed, no Content-Transfer-Encoding header at all,
	// must still extract correctly (identity "no encoding" path).
	msg := "" +
		"Subject: Plain nested test\r\n" +
		"Content-Type: multipart/mixed; boundary=\"outer\"\r\n" +
		"\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=\"inner\"\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain body text\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n"

	p := NewPlugin()
	got, err := p.Extract(context.Background(), "message/rfc822", bytes.NewReader([]byte(msg)))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got.Text != "plain body text" {
		t.Fatalf("Text = %q, want %q", got.Text, "plain body text")
	}
	if _, ok := got.Metadata["attachments"]; ok {
		t.Fatalf("expected no attachments key when there are none, got %v", got.Metadata["attachments"])
	}
}

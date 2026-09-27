package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	pdfreader "github.com/oarkflow/pdf/reader"

	"github.com/oarkflow/velocity/v2/api"
)

// --- PDF ---
//
// Uses github.com/oarkflow/pdf/reader, a pure-Go PDF parser operating
// directly on in-memory bytes (reader.Open) — deliberately NOT v1's
// approach of shelling out to the external `pdftotext` binary via
// os/exec, which only works if that binary happens to be installed in the
// deployment environment. This trades some text-layout fidelity (complex
// PDFs with unusual font encodings can extract imperfectly) for working
// out of the box with zero external dependencies, which is the more
// useful default for an embedded library.
func extractPDF(content []byte) (api.ExtractedContent, error) {
	r, err := pdfreader.Open(content)
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/pdf: %w", err)
	}
	numPages := r.NumPages()
	var sb strings.Builder
	for page := 0; page < numPages; page++ {
		text, err := r.ExtractText(page)
		if err != nil {
			return api.ExtractedContent{}, fmt.Errorf("extractor/pdf: extract page %d: %w", page, err)
		}
		if sb.Len() > 0 && text != "" {
			sb.WriteByte('\n')
		}
		sb.WriteString(text)
	}
	return api.ExtractedContent{
		Text:     strings.TrimSpace(sb.String()),
		Metadata: map[string]any{"pages": numPages},
	}, nil
}

// --- DOCX (OOXML) ---
//
// A .docx file is a ZIP archive; its main text lives in
// word/document.xml as a sequence of <w:t> run-text elements. This walks
// the XML token stream for <w:t> elements rather than using a regex,
// since w:t can carry an xml:space="preserve" attribute and nested
// namespaces that a regex would handle incorrectly.
func extractDOCX(content []byte) (api.ExtractedContent, error) {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/docx: not a valid zip/docx: %w", err)
	}

	var docXML *zip.File
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			docXML = f
			break
		}
	}
	if docXML == nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/docx: word/document.xml not found")
	}

	rc, err := docXML.Open()
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/docx: %w", err)
	}
	defer rc.Close()

	var sb strings.Builder
	paragraphs := 0
	dec := xml.NewDecoder(rc)
	inRun := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return api.ExtractedContent{}, fmt.Errorf("extractor/docx: xml: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "t":
				inRun = true
			case "p":
				paragraphs++
			}
		case xml.EndElement:
			if se.Name.Local == "t" {
				inRun = false
			}
		case xml.CharData:
			if inRun {
				sb.Write(se)
			}
		}
	}

	return api.ExtractedContent{
		Text:     strings.TrimSpace(sb.String()),
		Metadata: map[string]any{"paragraphs": paragraphs},
	}, nil
}

// --- Email (.eml, RFC 822) ---
//
// Uses stdlib net/mail for headers and mime/multipart for walking parts,
// preferring a text/plain part and falling back to stripping HTML from a
// text/html part via this package's existing extractHTML. Handles nested
// multipart (e.g. multipart/alternative inside multipart/mixed),
// quoted-printable/base64 Content-Transfer-Encoding decoding (real .eml
// messages very commonly use one of these — without decoding, extracted
// text would be garbled, not just incomplete), and lists attachment
// filenames in Metadata without extracting their (binary) content as text.
func extractEML(content []byte) (api.ExtractedContent, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		return api.ExtractedContent{}, fmt.Errorf("extractor/eml: %w", err)
	}

	meta := map[string]any{
		"subject": msg.Header.Get("Subject"),
		"from":    msg.Header.Get("From"),
		"to":      msg.Header.Get("To"),
		"date":    msg.Header.Get("Date"),
	}

	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// No/unparseable Content-Type: treat the whole body as plain text
		// (after decoding any Content-Transfer-Encoding), matching
		// net/mail's own permissive stance on malformed headers.
		body, readErr := io.ReadAll(msg.Body)
		if readErr != nil {
			return api.ExtractedContent{}, fmt.Errorf("extractor/eml: read body: %w", readErr)
		}
		body, err = decodeTransferEncoding(body, msg.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return api.ExtractedContent{}, err
		}
		return api.ExtractedContent{Text: strings.TrimSpace(string(body)), Metadata: meta}, nil
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		body, readErr := io.ReadAll(msg.Body)
		if readErr != nil {
			return api.ExtractedContent{}, fmt.Errorf("extractor/eml: read body: %w", readErr)
		}
		body, err = decodeTransferEncoding(body, msg.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return api.ExtractedContent{}, err
		}
		text := string(body)
		if mediaType == "text/html" {
			text = extractHTML(body)
		}
		return api.ExtractedContent{Text: strings.TrimSpace(text), Metadata: meta}, nil
	}

	boundary := params["boundary"]
	if boundary == "" {
		return api.ExtractedContent{}, fmt.Errorf("extractor/eml: multipart message missing boundary")
	}

	var parts emlParts
	if err := walkMultipart(msg.Body, boundary, &parts); err != nil {
		return api.ExtractedContent{}, err
	}

	text := parts.plainText
	if text == "" {
		text = extractHTML([]byte(parts.htmlText))
	}
	if len(parts.attachments) > 0 {
		meta["attachments"] = parts.attachments
	}
	return api.ExtractedContent{Text: strings.TrimSpace(text), Metadata: meta}, nil
}

// emlParts accumulates the plain/HTML body text and attachment filenames
// found while walking a (possibly nested) multipart message.
type emlParts struct {
	plainText   string
	htmlText    string
	attachments []string
}

// walkMultipart reads every part of a multipart body, decoding each
// part's Content-Transfer-Encoding, recursing into any part that is
// itself multipart/* (e.g. a multipart/alternative body nested inside an
// outer multipart/mixed message alongside attachments), and classifying
// each leaf part as body text or an attachment.
func walkMultipart(body io.Reader, boundary string, out *emlParts) error {
	mr := multipart.NewReader(body, boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("extractor/eml: multipart: %w", err)
		}

		partContentType := part.Header.Get("Content-Type")
		partMediaType, partParams, _ := mime.ParseMediaType(partContentType)
		partMediaType = strings.ToLower(partMediaType)

		if strings.HasPrefix(partMediaType, "multipart/") {
			nestedBoundary := partParams["boundary"]
			if nestedBoundary == "" {
				continue // malformed nested part: skip rather than fail the whole message
			}
			if err := walkMultipart(part, nestedBoundary, out); err != nil {
				return err
			}
			continue
		}

		if filename := attachmentFilename(part); filename != "" {
			out.attachments = append(out.attachments, filename)
			continue
		}

		partBody, err := io.ReadAll(part)
		if err != nil {
			return fmt.Errorf("extractor/eml: read part: %w", err)
		}
		partBody, err = decodeTransferEncoding(partBody, part.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return err
		}

		switch partMediaType {
		case "text/plain":
			out.plainText += string(partBody)
		case "text/html":
			out.htmlText += string(partBody)
		}
	}
	return nil
}

// attachmentFilename returns a part's attachment filename, checking
// Content-Disposition first (via the stdlib helper, which also covers
// RFC 2231 encoded filenames) and falling back to Content-Type's "name"
// parameter for older messages that only set that.
func attachmentFilename(part *multipart.Part) string {
	if fn := part.FileName(); fn != "" {
		return fn
	}
	if ct := part.Header.Get("Content-Type"); ct != "" {
		if _, params, err := mime.ParseMediaType(ct); err == nil {
			if fn := params["name"]; fn != "" {
				return fn
			}
		}
	}
	return ""
}

// decodeTransferEncoding decodes body per RFC 2045 Content-Transfer-
// Encoding. An empty/unrecognized encoding (including the common "7bit"/
// "8bit"/"binary" identity encodings) returns body unchanged.
func decodeTransferEncoding(body []byte, cte string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "quoted-printable":
		out, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, fmt.Errorf("extractor/eml: quoted-printable decode: %w", err)
		}
		return out, nil
	case "base64":
		// Email base64 bodies are commonly wrapped at ~76 chars; strip all
		// whitespace before decoding since encoding/base64 rejects it.
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(body))
		out, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("extractor/eml: base64 decode: %w", err)
		}
		return out, nil
	default:
		return body, nil
	}
}

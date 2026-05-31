package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// OfficeExtractor
// ---------------------------------------------------------------------------

// OfficeExtractor handles OOXML formats (docx, xlsx, pptx) and their legacy
// binary siblings (doc, xls, ppt – best-effort printable scrape).
//
// OOXML files are ZIP archives containing XML parts. We extract text from:
//   - docx: word/document.xml  + word/footnotes.xml + word/endnotes.xml
//   - xlsx: xl/sharedStrings.xml (cell strings) + xl/worksheets/*.xml (inline)
//   - pptx: ppt/slides/slide*.xml + ppt/notesSlides/notesSlide*.xml
//
// Legacy binary formats are handled by extractPrintableText (ASCII scrape).
type OfficeExtractor struct{}

func NewOfficeExtractor() *OfficeExtractor { return &OfficeExtractor{} }

func (e *OfficeExtractor) Supports(mt string) bool {
	switch mt {
	case
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/vnd.oasis.opendocument.text",
		"application/vnd.oasis.opendocument.spreadsheet",
		"application/vnd.oasis.opendocument.presentation":
		return true
	}
	return false
}

func (e *OfficeExtractor) Extract(content []byte, mt string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/office: empty content")
	}

	switch mt {
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return extractDocx(content)
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return extractXlsx(content)
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return extractPptx(content)
	case "application/vnd.oasis.opendocument.text",
		"application/vnd.oasis.opendocument.spreadsheet",
		"application/vnd.oasis.opendocument.presentation":
		return extractODF(content)
	default:
		// Legacy binary formats: best-effort printable scrape.
		return extractPrintableText(content), nil
	}
}

// ---------------------------------------------------------------------------
// OOXML helpers
// ---------------------------------------------------------------------------

// openZip opens content as a ZIP and returns a reader.
func openZip(content []byte) (*zip.Reader, error) {
	r, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("kg/office: not a valid ZIP/OOXML file: %w", err)
	}
	return r, nil
}

// readZipFile returns the contents of a named file inside a ZIP archive.
func readZipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 32<<20)) // 32 MB cap per part
		}
	}
	return nil, fmt.Errorf("kg/office: %q not found in archive", name)
}

// globZipFiles returns all file contents matching a glob pattern.
func globZipFiles(zr *zip.Reader, pattern string) [][]byte {
	var results [][]byte
	for _, f := range zr.File {
		matched, _ := filepath.Match(pattern, f.Name)
		if !matched {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 32<<20))
		rc.Close()
		if err != nil {
			continue
		}
		results = append(results, data)
	}
	return results
}

// xmlText extracts all character data from XML, skipping tags.
// Optional wantElements limits extraction to those element local names only
// (empty = all text nodes).
func xmlText(data []byte, wantElements ...string) string {
	wanted := make(map[string]bool, len(wantElements))
	for _, e := range wantElements {
		wanted[e] = true
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	var sb strings.Builder
	inWanted := len(wanted) == 0 // if no filter, always collect
	depth := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(wanted) > 0 && wanted[t.Name.Local] {
				inWanted = true
				depth = 0
			}
			if inWanted && len(wanted) > 0 {
				depth++
			}
		case xml.EndElement:
			if len(wanted) > 0 {
				if depth > 0 {
					depth--
				}
				if depth == 0 && wanted[t.Name.Local] {
					inWanted = false
				}
			}
		case xml.CharData:
			if inWanted {
				text := strings.TrimSpace(string(t))
				if text != "" {
					if sb.Len() > 0 {
						sb.WriteByte(' ')
					}
					sb.WriteString(text)
				}
			}
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// DOCX
// ---------------------------------------------------------------------------

func extractDocx(content []byte) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return extractPrintableText(content), nil
	}

	parts := []string{"word/document.xml", "word/footnotes.xml", "word/endnotes.xml"}
	var texts []string
	for _, part := range parts {
		data, err := readZipFile(zr, part)
		if err != nil {
			continue
		}
		// In OOXML, <w:t> elements hold the actual text runs.
		t := xmlText(data, "t")
		if t != "" {
			texts = append(texts, t)
		}
	}

	if len(texts) == 0 {
		return extractPrintableText(content), nil
	}
	return strings.Join(texts, " "), nil
}

// ---------------------------------------------------------------------------
// XLSX
// ---------------------------------------------------------------------------

func extractXlsx(content []byte) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return extractPrintableText(content), nil
	}

	var texts []string

	// Shared strings table – most string values live here.
	if ss, err := readZipFile(zr, "xl/sharedStrings.xml"); err == nil {
		// <si><t>value</t></si>
		t := xmlText(ss, "t")
		if t != "" {
			texts = append(texts, t)
		}
	}

	// Inline strings in worksheets.
	for _, data := range globZipFiles(zr, "xl/worksheets/sheet*.xml") {
		t := xmlText(data, "v", "t")
		if t != "" {
			texts = append(texts, t)
		}
	}

	if len(texts) == 0 {
		return extractPrintableText(content), nil
	}
	return strings.Join(texts, " "), nil
}

// ---------------------------------------------------------------------------
// PPTX
// ---------------------------------------------------------------------------

func extractPptx(content []byte) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return extractPrintableText(content), nil
	}

	var texts []string

	for _, data := range globZipFiles(zr, "ppt/slides/slide*.xml") {
		t := xmlText(data, "t")
		if t != "" {
			texts = append(texts, t)
		}
	}

	for _, data := range globZipFiles(zr, "ppt/notesSlides/notesSlide*.xml") {
		t := xmlText(data, "t")
		if t != "" {
			texts = append(texts, t)
		}
	}

	if len(texts) == 0 {
		return extractPrintableText(content), nil
	}
	return strings.Join(texts, " "), nil
}

// ---------------------------------------------------------------------------
// ODF (ODT / ODS / ODP)
// ---------------------------------------------------------------------------

// extractODF handles OpenDocument Format files (LibreOffice/OpenOffice).
// ODF files are also ZIP archives; text lives in content.xml.
func extractODF(content []byte) (string, error) {
	zr, err := openZip(content)
	if err != nil {
		return extractPrintableText(content), nil
	}

	data, err := readZipFile(zr, "content.xml")
	if err != nil {
		return extractPrintableText(content), nil
	}

	// ODF uses mixed namespaces; we want all text nodes.
	t := xmlText(data)
	if t == "" {
		return extractPrintableText(content), nil
	}
	return t, nil
}

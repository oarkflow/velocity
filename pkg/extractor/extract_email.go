package extractor

import (
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
)

// ---------------------------------------------------------------------------
// EmailExtractor
// ---------------------------------------------------------------------------

// EmailExtractor parses RFC-822 / MIME email messages.
// It extracts key headers and recursively walks MIME parts, collecting
// text/plain bodies (falling back to text/html when no plain part exists).
type EmailExtractor struct{}

func NewEmailExtractor() *EmailExtractor { return &EmailExtractor{} }

func (e *EmailExtractor) Supports(mt string) bool {
	return mt == "message/rfc822" || mt == "message/rfc2822" || mt == "message/email"
}

func (e *EmailExtractor) Extract(content []byte, _ string) (string, error) {
	if len(content) == 0 {
		return "", fmt.Errorf("kg/email: empty content")
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(content)))
	if err != nil {
		// Fall back to header+body split
		return fallbackEmail(content), nil
	}

	var parts []string

	// Collect key headers.
	for _, h := range []string{"From", "To", "Cc", "Subject", "Date"} {
		if v := msg.Header.Get(h); v != "" {
			parts = append(parts, h+": "+decodeEmailHeader(v))
		}
	}

	// Walk MIME tree.
	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}

	bodyBytes := &strings.Builder{}
	if err := walkMIMEPart(msg.Body, ct, msg.Header.Get("Content-Transfer-Encoding"), bodyBytes); err != nil {
		// Best-effort: read raw body
		buf := new(strings.Builder)
		rawBuf := make([]byte, 1<<20) // 1 MB cap
		n, _ := msg.Body.Read(rawBuf)
		buf.Write(rawBuf[:n])
		parts = append(parts, buf.String())
	} else if bodyBytes.Len() > 0 {
		parts = append(parts, bodyBytes.String())
	}

	return reSpaces.ReplaceAllString(strings.Join(parts, " "), " "), nil
}

// walkMIMEPart recursively extracts text from a MIME part.
func walkMIMEPart(body interface{ Read([]byte) (int, error) }, contentType, transferEncoding string, out *strings.Builder) error {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
		params = map[string]string{}
	}

	switch {
	case mediaType == "text/plain":
		raw, err := readAll(body, transferEncoding)
		if err != nil {
			return err
		}
		if out.Len() > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(strings.TrimSpace(string(raw)))

	case mediaType == "text/html":
		raw, err := readAll(body, transferEncoding)
		if err != nil {
			return err
		}
		extracted := extractHTML(raw)
		if out.Len() > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(extracted)

	case strings.HasPrefix(mediaType, "multipart/"):
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("kg/email: missing boundary in %s", mediaType)
		}
		mr := multipart.NewReader(body, boundary)
		// For multipart/alternative prefer plain; collect all for other types.
		var htmlFallback strings.Builder
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			partCT := p.Header.Get("Content-Type")
			if partCT == "" {
				partCT = "text/plain"
			}
			partEncoding := p.Header.Get("Content-Transfer-Encoding")
			partMedia, _, _ := mime.ParseMediaType(partCT)
			if mediaType == "multipart/alternative" && partMedia == "text/html" {
				_ = walkMIMEPart(p, partCT, partEncoding, &htmlFallback)
			} else {
				_ = walkMIMEPart(p, partCT, partEncoding, out)
			}
		}
		// Only use HTML fallback if we got nothing from plain parts.
		if out.Len() == 0 && htmlFallback.Len() > 0 {
			out.WriteString(htmlFallback.String())
		}
	}
	return nil
}

// readAll reads the body, unwrapping common Content-Transfer-Encoding values.
func readAll(r interface{ Read([]byte) (int, error) }, transferEncoding string) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	var reader interface{ Read([]byte) (int, error) } = r
	switch strings.ToLower(strings.TrimSpace(transferEncoding)) {
	case "quoted-printable":
		reader = quotedprintable.NewReader(r)
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, r)
	}

	for {
		n, err := reader.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func decodeEmailHeader(value string) string {
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

func fallbackEmail(content []byte) string {
	raw := strings.ReplaceAll(string(content), "\r\n", "\n")
	sections := strings.SplitN(raw, "\n\n", 2)
	headers := sections[0]
	body := ""
	if len(sections) == 2 {
		body = sections[1]
	}
	var parts []string
	for _, line := range strings.Split(headers, "\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "from:") ||
			strings.HasPrefix(lower, "to:") ||
			strings.HasPrefix(lower, "cc:") ||
			strings.HasPrefix(lower, "subject:") ||
			strings.HasPrefix(lower, "date:") {
			name, value, ok := strings.Cut(line, ":")
			if ok {
				parts = append(parts, strings.TrimSpace(name)+": "+decodeEmailHeader(strings.TrimSpace(value)))
			} else {
				parts = append(parts, strings.TrimSpace(line))
			}
		}
	}
	if strings.TrimSpace(body) != "" {
		encoding := ""
		for _, line := range strings.Split(headers, "\n") {
			if strings.HasPrefix(strings.ToLower(line), "content-transfer-encoding:") {
				_, value, _ := strings.Cut(line, ":")
				encoding = strings.TrimSpace(value)
				break
			}
		}
		reader := strings.NewReader(body)
		decoded, err := readAll(reader, encoding)
		if err == nil {
			body = string(decoded)
		}
		parts = append(parts, strings.TrimSpace(body))
	}
	return reSpaces.ReplaceAllString(strings.Join(parts, " "), " ")
}

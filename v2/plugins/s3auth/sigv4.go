// Package s3auth implements AWS Signature Version 4 request verification,
// ported faithfully from v1's pkg/s3/auth.go (canonical-request
// construction, signing-key derivation, presigned-URL parsing) — this is
// exactly the kind of proven-correct cryptographic/string-canonicalization
// logic that must not be reinvented sloppily.
//
// Unlike v1, this package holds no credential store: it is a pure
// verification library. Verify takes the accessKey/secretKey pair the
// caller already resolved (e.g. from plugin config) and checks the
// request's signature against it. A caller supporting multiple access
// keys should look up the secret for the request's parsed AccessKeyID
// before calling Verify and reject unknown access keys itself.
package s3auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sigV4Algorithm = "AWS4-HMAC-SHA256"

// Parsed represents parsed SigV4 authorization data, from either the
// Authorization header or a presigned URL's query parameters.
type Parsed struct {
	AccessKeyID   string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	IsPresigned   bool
}

// ParseAuthorization parses the Authorization header for SigV4.
func ParseAuthorization(authHeader string) (*Parsed, error) {
	if !strings.HasPrefix(authHeader, sigV4Algorithm+" ") {
		return nil, fmt.Errorf("s3auth: unsupported authorization algorithm")
	}
	parts := strings.TrimPrefix(authHeader, sigV4Algorithm+" ")

	parsed := &Parsed{}
	for _, part := range strings.Split(parts, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "Credential="):
			credParts := strings.Split(strings.TrimPrefix(part, "Credential="), "/")
			if len(credParts) < 4 {
				return nil, fmt.Errorf("s3auth: invalid credential format")
			}
			parsed.AccessKeyID = credParts[0]
			parsed.Date = credParts[1]
			parsed.Region = credParts[2]
			parsed.Service = credParts[3]
		case strings.HasPrefix(part, "SignedHeaders="):
			parsed.SignedHeaders = strings.Split(strings.TrimPrefix(part, "SignedHeaders="), ";")
		case strings.HasPrefix(part, "Signature="):
			parsed.Signature = strings.TrimPrefix(part, "Signature=")
		}
	}
	if parsed.AccessKeyID == "" || parsed.Signature == "" {
		return nil, fmt.Errorf("s3auth: incomplete authorization header")
	}
	return parsed, nil
}

// ParsePresignedURL parses presigned URL query parameters.
func ParsePresignedURL(query url.Values) (*Parsed, error) {
	if algorithm := query.Get("X-Amz-Algorithm"); algorithm != sigV4Algorithm {
		return nil, fmt.Errorf("s3auth: unsupported algorithm: %s", algorithm)
	}
	credParts := strings.Split(query.Get("X-Amz-Credential"), "/")
	if len(credParts) < 4 {
		return nil, fmt.Errorf("s3auth: invalid credential")
	}
	signature := query.Get("X-Amz-Signature")
	if signature == "" {
		return nil, fmt.Errorf("s3auth: missing signature")
	}
	return &Parsed{
		AccessKeyID:   credParts[0],
		Date:          credParts[1],
		Region:        credParts[2],
		Service:       credParts[3],
		SignedHeaders: strings.Split(query.Get("X-Amz-SignedHeaders"), ";"),
		Signature:     signature,
		IsPresigned:   true,
	}, nil
}

// Verify checks an incoming request's SigV4 signature (Authorization
// header or presigned URL query parameters) against accessKey/secretKey.
// It returns an error naming exactly what failed: missing auth, unknown
// access key, expired presigned URL, or signature mismatch.
func Verify(r *http.Request, accessKey, secretKey string) error {
	var parsed *Parsed
	var err error

	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parsed, err = ParseAuthorization(authHeader)
	} else if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		parsed, err = ParsePresignedURL(r.URL.Query())
		if err == nil {
			err = checkPresignedExpiry(r.URL.Query())
		}
	} else {
		return fmt.Errorf("s3auth: missing authentication")
	}
	if err != nil {
		return err
	}

	if parsed.AccessKeyID != accessKey {
		return fmt.Errorf("s3auth: unknown access key")
	}

	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.URL.Query().Get("X-Amz-Date")
	}
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
	}

	dateStamp := parsed.Date
	if dateStamp == "" && len(amzDate) >= 8 {
		dateStamp = amzDate[:8]
	}

	canonicalRequest := buildCanonicalRequest(r, parsed)
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, parsed.Region, parsed.Service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", sigV4Algorithm, amzDate, credentialScope, hashSHA256([]byte(canonicalRequest)))

	signingKey := computeSigningKey(secretKey, dateStamp, parsed.Region, parsed.Service)
	expected := hmacSHA256Hex(signingKey, []byte(stringToSign))

	if expected != parsed.Signature {
		return fmt.Errorf("s3auth: signature does not match")
	}
	return nil
}

func checkPresignedExpiry(query url.Values) error {
	amzDate := query.Get("X-Amz-Date")
	expires := query.Get("X-Amz-Expires")
	if amzDate == "" || expires == "" {
		return nil
	}
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("s3auth: invalid X-Amz-Date")
	}
	expSecs, _ := strconv.Atoi(expires)
	if time.Now().After(t.Add(time.Duration(expSecs) * time.Second)) {
		return fmt.Errorf("s3auth: presigned URL has expired")
	}
	return nil
}

func buildCanonicalRequest(r *http.Request, parsed *Parsed) string {
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := buildCanonicalQueryString(r.URL.Query(), parsed.IsPresigned)

	signedHeaders := append([]string(nil), parsed.SignedHeaders...)
	sort.Strings(signedHeaders)

	var canonicalHeaders strings.Builder
	for _, header := range signedHeaders {
		value := r.Header.Get(header)
		if strings.EqualFold(header, "host") && value == "" {
			value = r.Host
		}
		canonicalHeaders.WriteString(strings.ToLower(header))
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteString("\n")
	}
	signedHeadersStr := strings.Join(parsed.SignedHeaders, ";")

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		r.Method, canonicalURI, canonicalQueryString, canonicalHeaders.String(), signedHeadersStr, payloadHash)
}

func buildCanonicalQueryString(query url.Values, isPresigned bool) string {
	filtered := make(url.Values)
	for k, v := range query {
		if isPresigned && k == "X-Amz-Signature" {
			continue
		}
		filtered[k] = v
	}
	keys := make([]string, 0, len(filtered))
	for k := range filtered {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range filtered[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func computeSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hmacSHA256Hex(key, data []byte) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

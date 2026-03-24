package velocity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3 Signature V4 authentication implementation

const (
	sigV4Algorithm  = "AWS4-HMAC-SHA256"
	s3ServiceName   = "s3"
	defaultS3Region = "us-east-1"
	credPrefix      = "s3:cred:"
	credSecretPrefix = "s3:secret:"
)

// S3Credential represents an S3 access key pair
type S3Credential struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey  string    `json:"secret_access_key"`
	UserID          string    `json:"user_id"`
	Description     string    `json:"description"`
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// S3CredentialStore manages S3 access credentials
type S3CredentialStore struct {
	db *DB
}

// NewS3CredentialStore creates a new credential store
func NewS3CredentialStore(db *DB) *S3CredentialStore {
	return &S3CredentialStore{db: db}
}

// GenerateCredentials creates new S3 access key pair for a user
func (cs *S3CredentialStore) GenerateCredentials(userID, description string) (*S3Credential, error) {
	accessKey, err := generateAccessKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access key: %w", err)
	}

	secretKey, err := generateSecretAccessKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret key: %w", err)
	}

	cred := &S3Credential{
		AccessKeyID:     accessKey,
		SecretAccessKey:  secretKey,
		UserID:          userID,
		Description:     description,
		Active:          true,
		CreatedAt:       time.Now().UTC(),
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}

	if err := cs.db.PutWithTTL([]byte(credPrefix+accessKey), data, 0); err != nil {
		return nil, err
	}

	return cred, nil
}

// GetCredential retrieves credentials by access key ID
func (cs *S3CredentialStore) GetCredential(accessKeyID string) (*S3Credential, error) {
	data, err := cs.db.Get([]byte(credPrefix + accessKeyID))
	if err != nil {
		return nil, fmt.Errorf("credential not found")
	}

	var cred S3Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}

	if !cred.Active {
		return nil, fmt.Errorf("credential is inactive")
	}

	if cred.ExpiresAt != nil && time.Now().After(*cred.ExpiresAt) {
		return nil, fmt.Errorf("credential has expired")
	}

	return &cred, nil
}

// DeleteCredential deactivates a credential
func (cs *S3CredentialStore) DeleteCredential(accessKeyID string) error {
	cred, err := cs.GetCredential(accessKeyID)
	if err != nil {
		return err
	}

	cred.Active = false
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	return cs.db.PutWithTTL([]byte(credPrefix+accessKeyID), data, 0)
}

// ListCredentials lists all credentials for a user
func (cs *S3CredentialStore) ListCredentials(userID string) ([]*S3Credential, error) {
	keys, err := cs.db.Keys(credPrefix + "*")
	if err != nil {
		return nil, err
	}

	var creds []*S3Credential
	for _, key := range keys {
		data, err := cs.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var cred S3Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			continue
		}

		if cred.UserID == userID && cred.Active {
			creds = append(creds, &cred)
		}
	}

	return creds, nil
}

// SigV4Auth handles AWS Signature V4 verification
type SigV4Auth struct {
	credStore *S3CredentialStore
	region    string
}

// NewSigV4Auth creates a new SigV4 authenticator
func NewSigV4Auth(credStore *S3CredentialStore, region string) *SigV4Auth {
	if region == "" {
		region = defaultS3Region
	}
	return &SigV4Auth{
		credStore: credStore,
		region:    region,
	}
}

// ParsedSigV4 represents parsed SigV4 authorization data
type ParsedSigV4 struct {
	AccessKeyID   string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	IsPresigned   bool
}

// ParseAuthorization parses the Authorization header for SigV4
func (sa *SigV4Auth) ParseAuthorization(authHeader string) (*ParsedSigV4, error) {
	if !strings.HasPrefix(authHeader, sigV4Algorithm+" ") {
		return nil, fmt.Errorf("unsupported authorization algorithm")
	}

	parts := strings.TrimPrefix(authHeader, sigV4Algorithm+" ")

	parsed := &ParsedSigV4{}
	for _, part := range strings.Split(parts, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "Credential=") {
			credStr := strings.TrimPrefix(part, "Credential=")
			credParts := strings.Split(credStr, "/")
			if len(credParts) < 4 {
				return nil, fmt.Errorf("invalid credential format")
			}
			parsed.AccessKeyID = credParts[0]
			parsed.Date = credParts[1]
			parsed.Region = credParts[2]
			parsed.Service = credParts[3]
		} else if strings.HasPrefix(part, "SignedHeaders=") {
			headersStr := strings.TrimPrefix(part, "SignedHeaders=")
			parsed.SignedHeaders = strings.Split(headersStr, ";")
		} else if strings.HasPrefix(part, "Signature=") {
			parsed.Signature = strings.TrimPrefix(part, "Signature=")
		}
	}

	if parsed.AccessKeyID == "" || parsed.Signature == "" {
		return nil, fmt.Errorf("incomplete authorization header")
	}

	return parsed, nil
}

// ParsePresignedURL parses presigned URL query parameters
func (sa *SigV4Auth) ParsePresignedURL(query url.Values) (*ParsedSigV4, error) {
	algorithm := query.Get("X-Amz-Algorithm")
	if algorithm != sigV4Algorithm {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	credential := query.Get("X-Amz-Credential")
	credParts := strings.Split(credential, "/")
	if len(credParts) < 4 {
		return nil, fmt.Errorf("invalid credential")
	}

	signedHeaders := strings.Split(query.Get("X-Amz-SignedHeaders"), ";")
	signature := query.Get("X-Amz-Signature")

	if signature == "" {
		return nil, fmt.Errorf("missing signature")
	}

	return &ParsedSigV4{
		AccessKeyID:   credParts[0],
		Date:          credParts[1],
		Region:        credParts[2],
		Service:       credParts[3],
		SignedHeaders: signedHeaders,
		Signature:     signature,
		IsPresigned:   true,
	}, nil
}

// VerifyRequest verifies an incoming S3 request
func (sa *SigV4Auth) VerifyRequest(r *http.Request) (*S3Credential, error) {
	var parsed *ParsedSigV4
	var err error

	// Check for Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parsed, err = sa.ParseAuthorization(authHeader)
		if err != nil {
			return nil, err
		}
	} else if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		// Check for presigned URL
		parsed, err = sa.ParsePresignedURL(r.URL.Query())
		if err != nil {
			return nil, err
		}

		// Check expiration for presigned URLs
		amzDate := r.URL.Query().Get("X-Amz-Date")
		expires := r.URL.Query().Get("X-Amz-Expires")
		if amzDate != "" && expires != "" {
			t, err := time.Parse("20060102T150405Z", amzDate)
			if err != nil {
				return nil, fmt.Errorf("invalid X-Amz-Date")
			}
			var expSecs int
			fmt.Sscanf(expires, "%d", &expSecs)
			if time.Now().After(t.Add(time.Duration(expSecs) * time.Second)) {
				return nil, fmt.Errorf("presigned URL has expired")
			}
		}
	} else {
		return nil, fmt.Errorf("missing authentication")
	}

	// Retrieve credentials
	cred, err := sa.credStore.GetCredential(parsed.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("invalid access key: %w", err)
	}

	// Compute expected signature
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

	// Build canonical request
	canonicalRequest := sa.buildCanonicalRequest(r, parsed)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, parsed.Region, parsed.Service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		sigV4Algorithm,
		amzDate,
		credentialScope,
		hashSHA256([]byte(canonicalRequest)),
	)

	// Compute signing key
	signingKey := computeSigningKey(cred.SecretAccessKey, dateStamp, parsed.Region, parsed.Service)

	// Compute signature
	expectedSignature := hmacSHA256Hex(signingKey, []byte(stringToSign))

	if expectedSignature != parsed.Signature {
		return nil, fmt.Errorf("signature does not match")
	}

	return cred, nil
}

func (sa *SigV4Auth) buildCanonicalRequest(r *http.Request, parsed *ParsedSigV4) string {
	// HTTP method
	method := r.Method

	// Canonical URI
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string
	canonicalQueryString := buildCanonicalQueryString(r.URL.Query(), parsed.IsPresigned)

	// Canonical headers
	var canonicalHeaders strings.Builder
	sort.Strings(parsed.SignedHeaders)
	for _, header := range parsed.SignedHeaders {
		value := r.Header.Get(header)
		if header == "host" && value == "" {
			value = r.Host
		}
		canonicalHeaders.WriteString(strings.ToLower(header))
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteString("\n")
	}

	signedHeadersStr := strings.Join(parsed.SignedHeaders, ";")

	// Payload hash
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		if parsed.IsPresigned {
			payloadHash = "UNSIGNED-PAYLOAD"
		} else {
			payloadHash = "UNSIGNED-PAYLOAD"
		}
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	)
}

func buildCanonicalQueryString(query url.Values, isPresigned bool) string {
	// Remove X-Amz-Signature from presigned queries
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

// computeSigningKey derives the signing key for SigV4
func computeSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
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

func generateAccessKeyID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "VK" + strings.ToUpper(hex.EncodeToString(b)), nil
}

func generateSecretAccessKey() (string, error) {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

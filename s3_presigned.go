package velocity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// PresignedURLGenerator generates and validates presigned URLs
type PresignedURLGenerator struct {
	credStore *S3CredentialStore
	region    string
	endpoint  string // Base URL like "http://localhost:8080"
}

// NewPresignedURLGenerator creates a new presigned URL generator
func NewPresignedURLGenerator(credStore *S3CredentialStore, region, endpoint string) *PresignedURLGenerator {
	if region == "" {
		region = defaultS3Region
	}
	return &PresignedURLGenerator{
		credStore: credStore,
		region:    region,
		endpoint:  strings.TrimRight(endpoint, "/"),
	}
}

// GeneratePresignedGetURL generates a presigned URL for downloading an object
func (pg *PresignedURLGenerator) GeneratePresignedGetURL(accessKeyID, bucket, key string, expiration time.Duration) (string, error) {
	return pg.generatePresignedURL("GET", accessKeyID, bucket, key, expiration, nil)
}

// GeneratePresignedPutURL generates a presigned URL for uploading an object
func (pg *PresignedURLGenerator) GeneratePresignedPutURL(accessKeyID, bucket, key, contentType string, expiration time.Duration) (string, error) {
	headers := map[string]string{}
	if contentType != "" {
		headers["content-type"] = contentType
	}
	return pg.generatePresignedURL("PUT", accessKeyID, bucket, key, expiration, headers)
}

func (pg *PresignedURLGenerator) generatePresignedURL(method, accessKeyID, bucket, key string, expiration time.Duration, extraHeaders map[string]string) (string, error) {
	if expiration > 7*24*time.Hour {
		return "", fmt.Errorf("presigned URL expiration cannot exceed 7 days")
	}
	if expiration <= 0 {
		expiration = 15 * time.Minute
	}

	cred, err := pg.credStore.GetCredential(accessKeyID)
	if err != nil {
		return "", fmt.Errorf("invalid access key: %w", err)
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	expiresSeconds := int(expiration.Seconds())

	objectPath := fmt.Sprintf("/s3/%s/%s", bucket, key)

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, pg.region, s3ServiceName)
	credential := fmt.Sprintf("%s/%s", accessKeyID, credentialScope)

	// Build query parameters
	params := url.Values{}
	params.Set("X-Amz-Algorithm", sigV4Algorithm)
	params.Set("X-Amz-Credential", credential)
	params.Set("X-Amz-Date", amzDate)
	params.Set("X-Amz-Expires", fmt.Sprintf("%d", expiresSeconds))

	signedHeaders := []string{"host"}
	for k := range extraHeaders {
		signedHeaders = append(signedHeaders, strings.ToLower(k))
	}
	params.Set("X-Amz-SignedHeaders", strings.Join(signedHeaders, ";"))

	// Build canonical request
	canonicalQueryString := params.Encode()

	host := strings.TrimPrefix(pg.endpoint, "http://")
	host = strings.TrimPrefix(host, "https://")

	var canonicalHeaders strings.Builder
	canonicalHeaders.WriteString("host:" + host + "\n")
	for k, v := range extraHeaders {
		canonicalHeaders.WriteString(strings.ToLower(k) + ":" + v + "\n")
	}

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\nUNSIGNED-PAYLOAD",
		method,
		objectPath,
		canonicalQueryString,
		canonicalHeaders.String(),
		strings.Join(signedHeaders, ";"),
	)

	// String to sign
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		sigV4Algorithm,
		amzDate,
		credentialScope,
		hashSHA256([]byte(canonicalRequest)),
	)

	// Signing key
	signingKey := computeSigningKey(cred.SecretAccessKey, dateStamp, pg.region, s3ServiceName)

	// Signature
	signatureHMAC := hmac.New(sha256.New, signingKey)
	signatureHMAC.Write([]byte(stringToSign))
	signature := hex.EncodeToString(signatureHMAC.Sum(nil))

	params.Set("X-Amz-Signature", signature)

	presignedURL := fmt.Sprintf("%s%s?%s", pg.endpoint, objectPath, params.Encode())
	return presignedURL, nil
}

// ValidatePresignedURL validates a presigned URL's signature and expiration
func (pg *PresignedURLGenerator) ValidatePresignedURL(rawURL string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL")
	}

	query := u.Query()

	algorithm := query.Get("X-Amz-Algorithm")
	if algorithm != sigV4Algorithm {
		return "", "", fmt.Errorf("unsupported algorithm")
	}

	amzDate := query.Get("X-Amz-Date")
	expiresStr := query.Get("X-Amz-Expires")
	credential := query.Get("X-Amz-Credential")

	if amzDate == "" || expiresStr == "" || credential == "" {
		return "", "", fmt.Errorf("missing required presigned URL parameters")
	}

	// Check expiration
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return "", "", fmt.Errorf("invalid date format")
	}

	var expSecs int
	fmt.Sscanf(expiresStr, "%d", &expSecs)
	if time.Now().After(t.Add(time.Duration(expSecs) * time.Second)) {
		return "", "", fmt.Errorf("presigned URL has expired")
	}

	// Extract bucket and key from path
	path := strings.TrimPrefix(u.Path, "/s3/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid path")
	}

	return parts[0], parts[1], nil
}

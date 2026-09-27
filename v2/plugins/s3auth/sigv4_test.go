package s3auth

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

const (
	testAccessKey = "VKTESTACCESSKEY"
	testSecretKey = "test-secret-key-do-not-use-in-prod"
	testRegion    = "us-east-1"
)

// signRequest mirrors what a real SigV4 client does, so tests can produce
// a validly-signed request without needing an external SDK.
func signRequest(r *http.Request, accessKey, secretKey string, at time.Time) {
	amzDate := at.UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("Host", r.Host)

	signedHeaders := []string{"host", "x-amz-date"}
	parsed := &Parsed{Region: testRegion, Service: "s3", SignedHeaders: signedHeaders}
	canonicalRequest := buildCanonicalRequest(r, parsed)
	credentialScope := dateStamp + "/" + testRegion + "/s3/aws4_request"
	stringToSign := sigV4Algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + hashSHA256([]byte(canonicalRequest))
	signingKey := computeSigningKey(secretKey, dateStamp, testRegion, "s3")
	signature := hmacSHA256Hex(signingKey, []byte(stringToSign))

	authHeader := sigV4Algorithm + " Credential=" + accessKey + "/" + dateStamp + "/" + testRegion + "/s3/aws4_request," +
		"SignedHeaders=" + "host;x-amz-date" + ",Signature=" + signature
	r.Header.Set("Authorization", authHeader)
}

func newTestRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://example.com/api/buckets/b1/objects/k1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "example.com"
	return r
}

func TestVerify_ValidSignature(t *testing.T) {
	r := newTestRequest(t)
	signRequest(r, testAccessKey, testSecretKey, time.Now())

	if err := Verify(r, testAccessKey, testSecretKey); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerify_TamperedHeaderRejected(t *testing.T) {
	r := newTestRequest(t)
	signRequest(r, testAccessKey, testSecretKey, time.Now())

	// Tamper with a signed header (host) after signing — signature must
	// no longer match.
	r.Host = "attacker.example.com"
	r.Header.Set("Host", r.Host)

	if err := Verify(r, testAccessKey, testSecretKey); err == nil {
		t.Fatal("expected tampered request to fail verification, got nil error")
	}
}

func TestVerify_WrongSecretRejected(t *testing.T) {
	r := newTestRequest(t)
	signRequest(r, testAccessKey, testSecretKey, time.Now())

	if err := Verify(r, testAccessKey, "wrong-secret"); err == nil {
		t.Fatal("expected verification with wrong secret to fail, got nil error")
	}
}

func TestVerify_UnknownAccessKeyRejected(t *testing.T) {
	r := newTestRequest(t)
	signRequest(r, testAccessKey, testSecretKey, time.Now())

	if err := Verify(r, "some-other-access-key", testSecretKey); err == nil {
		t.Fatal("expected unknown access key to fail verification, got nil error")
	}
}

func TestVerify_MissingAuthRejected(t *testing.T) {
	r := newTestRequest(t)
	if err := Verify(r, testAccessKey, testSecretKey); err == nil {
		t.Fatal("expected request with no auth to fail verification, got nil error")
	}
}

func TestPresignedURL_ExpiredRejected(t *testing.T) {
	q := url.Values{}
	q.Set("X-Amz-Algorithm", sigV4Algorithm)
	q.Set("X-Amz-Credential", testAccessKey+"/20200101/us-east-1/s3/aws4_request")
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", "deadbeef")
	q.Set("X-Amz-Date", "20200101T000000Z")
	q.Set("X-Amz-Expires", "60")

	r, err := http.NewRequest(http.MethodGet, "http://example.com/api/buckets/b1/objects/k1?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.URL.RawQuery = q.Encode()

	if err := Verify(r, testAccessKey, testSecretKey); err == nil {
		t.Fatal("expected long-expired presigned URL to be rejected, got nil error")
	}
}

func TestParseAuthorization_Malformed(t *testing.T) {
	if _, err := ParseAuthorization("Basic garbage"); err == nil {
		t.Fatal("expected non-SigV4 authorization header to be rejected")
	}
	if _, err := ParseAuthorization(sigV4Algorithm + " Credential=onlyonepart"); err == nil {
		t.Fatal("expected incomplete credential to be rejected")
	}
}

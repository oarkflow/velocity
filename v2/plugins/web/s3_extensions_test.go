package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// newTestPluginWithS3Keys is like newTestPlugin but also configures SigV4
// access/secret keys, so requireAuth's alternate auth path is reachable.
func newTestPluginWithS3Keys(t *testing.T, accessKey, secretKey string) (*Plugin, *fakeObjectStore) {
	t.Helper()
	reg := newFakeRegistry()
	kv := newFakeKV()
	obj := newFakeObjectStore()
	reg.Provide("kv", kv)
	reg.Provide("object", obj)
	reg.Provide("auth.jwt", &fakeAuth{validToken: "good-token"})

	cfg := &fakeConfig{data: map[string]any{
		"s3_access_key": accessKey,
		"s3_secret_key": secretKey,
	}}
	k := &fakeKernel{reg: reg, cfg: cfg, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, obj
}

func TestRouteTable_NoDuplicatesAfterS3Extensions(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	t2, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v (duplicate route registration)", err)
	}
	if len(t2.patterns()) < 14 {
		t.Fatalf("expected at least 14 registered routes, got %d: %v", len(t2.patterns()), t2.patterns())
	}
}

func TestHeadObject(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	obj.PutObject(context.Background(), "b1", "k1", strings.NewReader("hello world"), api.ObjectMeta{})

	t2, err := p.buildMux()
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/api/buckets/b1/objects/k1", nil)
	t2.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("HEAD must not return a body, got %d bytes", rr.Body.Len())
	}
	if rr.Header().Get("Content-Length") == "" {
		t.Fatal("expected Content-Length header on HEAD response")
	}
}

func TestGetObjectRange(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	obj.PutObject(context.Background(), "b1", "k1", strings.NewReader("0123456789"), api.ObjectMeta{})

	t2, err := p.buildMux()
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/buckets/b1/objects/k1", nil)
	req.Header.Set("Range", "bytes=2-5")
	t2.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("expected 206, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "2345" {
		t.Fatalf("expected range body %q, got %q", "2345", got)
	}
	if cr := rr.Header().Get("Content-Range"); cr != "bytes 2-5/10" {
		t.Fatalf("unexpected Content-Range: %q", cr)
	}
}

func TestGetObjectRange_OpenEnded(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	obj.PutObject(context.Background(), "b1", "k1", strings.NewReader("0123456789"), api.ObjectMeta{})

	t2, _ := p.buildMux()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/buckets/b1/objects/k1", nil)
	req.Header.Set("Range", "bytes=7-")
	t2.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("expected 206, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "789" {
		t.Fatalf("expected %q, got %q", "789", got)
	}
}

func TestCopyObject(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	obj.CreateBucket(context.Background(), "b2")
	obj.PutObject(context.Background(), "b1", "src", strings.NewReader("copy me"), api.ObjectMeta{})

	t2, _ := p.buildMux()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/buckets/b2/objects/dst/copy", nil)
	req.Header.Set("X-Copy-Source", "b1/src")
	t2.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr2 := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/api/buckets/b2/objects/dst", nil)
	t2.mux.ServeHTTP(rr2, getReq)
	if rr2.Body.String() != "copy me" {
		t.Fatalf("expected copied body %q, got %q", "copy me", rr2.Body.String())
	}
}

func TestMultipartUploadRoundTrip(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	t2, _ := p.buildMux()

	// Initiate
	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/buckets/b1/objects/big/uploads", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("initiate: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var initResp struct {
		UploadID string `json:"uploadId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &initResp); err != nil {
		t.Fatalf("decode initiate response: %v", err)
	}
	if initResp.UploadID == "" {
		t.Fatal("expected non-empty uploadId")
	}

	// Upload two parts
	part1 := httptest.NewRequest(http.MethodPut, "/api/buckets/b1/objects/big/uploads/"+initResp.UploadID+"/1", strings.NewReader("hello "))
	rr1 := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr1, part1)
	etag1 := rr1.Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("expected ETag for part 1")
	}

	part2 := httptest.NewRequest(http.MethodPut, "/api/buckets/b1/objects/big/uploads/"+initResp.UploadID+"/2", strings.NewReader("world"))
	rr2 := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr2, part2)
	etag2 := rr2.Header().Get("ETag")
	if etag2 == "" {
		t.Fatal("expected ETag for part 2")
	}

	// Complete
	completeBody := `{"parts":[{"PartNumber":1,"ETag":"` + etag1 + `"},{"PartNumber":2,"ETag":"` + etag2 + `"}]}`
	completeReq := httptest.NewRequest(http.MethodPost, "/api/buckets/b1/objects/big/uploads/"+initResp.UploadID+"/complete", strings.NewReader(completeBody))
	rrC := httptest.NewRecorder()
	t2.mux.ServeHTTP(rrC, completeReq)
	if rrC.Code != http.StatusOK {
		t.Fatalf("complete: expected 200, got %d: %s", rrC.Code, rrC.Body.String())
	}

	// Verify assembled object
	getReq := httptest.NewRequest(http.MethodGet, "/api/buckets/b1/objects/big", nil)
	rrGet := httptest.NewRecorder()
	t2.mux.ServeHTTP(rrGet, getReq)
	if got := rrGet.Body.String(); got != "hello world" {
		t.Fatalf("expected assembled body %q, got %q", "hello world", got)
	}
}

func TestMultipartAbort(t *testing.T) {
	p, _, obj := newTestPlugin(t, false, false)
	obj.CreateBucket(context.Background(), "b1")
	t2, _ := p.buildMux()

	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/buckets/b1/objects/big/uploads", nil))
	var initResp struct {
		UploadID string `json:"uploadId"`
	}
	json.Unmarshal(rr.Body.Bytes(), &initResp)

	abortRR := httptest.NewRecorder()
	t2.mux.ServeHTTP(abortRR, httptest.NewRequest(http.MethodDelete, "/api/buckets/b1/objects/big/uploads/"+initResp.UploadID, nil))
	if abortRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", abortRR.Code, abortRR.Body.String())
	}

	// Aborting again must fail — the upload no longer exists.
	abortAgainRR := httptest.NewRecorder()
	t2.mux.ServeHTTP(abortAgainRR, httptest.NewRequest(http.MethodDelete, "/api/buckets/b1/objects/big/uploads/"+initResp.UploadID, nil))
	if abortAgainRR.Code == http.StatusNoContent {
		t.Fatal("expected second abort of the same upload to fail")
	}
}

func TestSigV4Auth_ValidSignatureAccepted(t *testing.T) {
	const accessKey, secretKey = "TESTKEY", "test-secret"
	p, obj := newTestPluginWithS3Keys(t, accessKey, secretKey)
	obj.CreateBucket(context.Background(), "b1")
	t2, _ := p.buildMux()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/buckets/b1/objects", nil)
	req.Host = "example.com"
	signRequestForTest(req, accessKey, secretKey)

	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid SigV4 signature, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSigV4Auth_InvalidSignatureRejected(t *testing.T) {
	const accessKey, secretKey = "TESTKEY", "test-secret"
	p, _ := newTestPluginWithS3Keys(t, accessKey, secretKey)
	t2, _ := p.buildMux()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/buckets/b1/objects", nil)
	req.Host = "example.com"
	signRequestForTest(req, accessKey, "wrong-secret")

	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid SigV4 signature, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSigV4Auth_RejectedWhenNotConfigured(t *testing.T) {
	// Bearer-auth plugin, no SigV4 keys configured at all.
	p, _, _ := newTestPlugin(t, true, false)
	t2, _ := p.buildMux()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/buckets/b1/objects", nil)
	req.Host = "example.com"
	signRequestForTest(req, "any-key", "any-secret")

	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when SigV4 isn't configured, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBearerAuth_StillWorksAlongsideSigV4Config(t *testing.T) {
	const accessKey, secretKey = "TESTKEY", "test-secret"
	p, obj := newTestPluginWithS3Keys(t, accessKey, secretKey)
	obj.CreateBucket(context.Background(), "b1")
	t2, _ := p.buildMux()

	req := httptest.NewRequest(http.MethodGet, "/api/buckets/b1/objects", nil)
	req.Header.Set("Authorization", "Bearer good-token")

	rr := httptest.NewRecorder()
	t2.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with a valid bearer token even when SigV4 is also configured, got %d: %s", rr.Code, rr.Body.String())
	}
}

// signRequestForTest signs r with a minimal SigV4 implementation
// (independent of plugins/s3auth's unexported internals, which this
// package can't reach directly) so tests can exercise the alternate
// SigV4 auth path in requireAuth against a real, correctly-signed
// request — matching exactly what plugins/s3auth.Verify checks.
func signRequestForTest(r *http.Request, accessKey, secretKey string) {
	const amzDate = "20250101T000000Z"
	const dateStamp = "20250101"
	const region = "us-east-1"
	const service = "s3"

	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("Host", r.Host)

	signedHeaders := []string{"host", "x-amz-date"}
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		v := r.Header.Get(h)
		if strings.EqualFold(h, "host") && v == "" {
			v = r.Host
		}
		canonicalHeaders.WriteString(strings.ToLower(h) + ":" + strings.TrimSpace(v) + "\n")
	}
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		"", // no query string in these tests
		canonicalHeaders.String(),
		strings.Join(signedHeaders, ";"),
		"UNSIGNED-PAYLOAD",
	}, "\n")

	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + sha256Hex(canonicalRequest)

	kDate := hmacBytes([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacBytes(kDate, region)
	kService := hmacBytes(kRegion, service)
	signingKey := hmacBytes(kService, "aws4_request")
	signature := hex.EncodeToString(hmacBytes(signingKey, stringToSign))

	authHeader := "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + credentialScope + "," +
		"SignedHeaders=" + strings.Join(signedHeaders, ";") + ",Signature=" + signature
	r.Header.Set("Authorization", authHeader)
}

func hmacBytes(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

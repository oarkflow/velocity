package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// --- minimal in-test fakes, so this package's tests never block on the
// real kv/object/auth plugins existing yet. ---

type fakeKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeKV() *fakeKV { return &fakeKV{data: map[string][]byte{}} }

func (f *fakeKV) Put(ctx context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}
func (f *fakeKV) PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return f.Put(ctx, key, value)
}
func (f *fakeKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	return v, ok, nil
}
func (f *fakeKV) Delete(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}
func (f *fakeKV) Exists(ctx context.Context, key string) (bool, error) {
	_, ok, err := f.Get(ctx, key)
	return ok, err
}
func (f *fakeKV) Incr(ctx context.Context, key string, delta int64) (int64, error) { return 0, nil }
func (f *fakeKV) Keys(ctx context.Context, pattern string) ([]string, error)       { return nil, nil }
func (f *fakeKV) Scan(ctx context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
	return nil, "", nil
}

var _ api.KVService = (*fakeKV)(nil)

type fakeObjectStore struct {
	mu       sync.Mutex
	buckets  map[string]bool
	objects  map[string][]byte // bucket/key -> data
	uploads  map[string]map[int][]byte
	nextVers int
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{buckets: map[string]bool{}, objects: map[string][]byte{}, uploads: map[string]map[int][]byte{}}
}

func (f *fakeObjectStore) CreateBucket(ctx context.Context, bucket string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[bucket] = true
	return nil
}
func (f *fakeObjectStore) DeleteBucket(ctx context.Context, bucket string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.buckets, bucket)
	return nil
}
func (f *fakeObjectStore) PutObject(ctx context.Context, bucket, key string, r io.Reader, meta api.ObjectMeta) (api.ObjectMeta, error) {
	data, _ := io.ReadAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[bucket+"/"+key] = data
	meta.ETag = "etag-fake"
	meta.VersionID = "v1"
	meta.Size = int64(len(data))
	return meta, nil
}
func (f *fakeObjectStore) GetObject(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, api.ObjectMeta, error) {
	f.mu.Lock()
	data, ok := f.objects[bucket+"/"+key]
	f.mu.Unlock()
	if !ok {
		return nil, api.ObjectMeta{}, io.EOF
	}
	return io.NopCloser(bytes.NewReader(data)), api.ObjectMeta{Bucket: bucket, Key: key, ETag: "etag-fake"}, nil
}
func (f *fakeObjectStore) DeleteObject(ctx context.Context, bucket, key, versionID string, bypassGovernance bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, bucket+"/"+key)
	return nil
}
func (f *fakeObjectStore) ListObjects(ctx context.Context, bucket, prefix string) ([]api.ObjectMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.ObjectMeta
	for k := range f.objects {
		if strings.HasPrefix(k, bucket+"/") {
			out = append(out, api.ObjectMeta{Bucket: bucket, Key: strings.TrimPrefix(k, bucket+"/")})
		}
	}
	return out, nil
}
func (f *fakeObjectStore) PutRetention(ctx context.Context, bucket, key string, p api.RetentionPolicy) error {
	return nil
}
func (f *fakeObjectStore) SetLifecycle(ctx context.Context, bucket string, rules []api.LifecycleRule) error {
	return nil
}

func (f *fakeObjectStore) HeadObject(ctx context.Context, bucket, key, versionID string) (api.ObjectMeta, error) {
	f.mu.Lock()
	data, ok := f.objects[bucket+"/"+key]
	f.mu.Unlock()
	if !ok {
		return api.ObjectMeta{}, io.EOF
	}
	return api.ObjectMeta{Bucket: bucket, Key: key, ETag: "etag-fake", VersionID: "v1", Size: int64(len(data))}, nil
}

func (f *fakeObjectStore) GetObjectRange(ctx context.Context, bucket, key, versionID string, start, end int64) (io.ReadCloser, api.ObjectMeta, error) {
	f.mu.Lock()
	data, ok := f.objects[bucket+"/"+key]
	f.mu.Unlock()
	if !ok {
		return nil, api.ObjectMeta{}, io.EOF
	}
	size := int64(len(data))
	if end == -1 || end >= size {
		end = size - 1
	}
	if start < 0 || start > end {
		return nil, api.ObjectMeta{}, fmt.Errorf("invalid range")
	}
	meta := api.ObjectMeta{Bucket: bucket, Key: key, ETag: "etag-fake", VersionID: "v1", Size: size}
	return io.NopCloser(bytes.NewReader(data[start : end+1])), meta, nil
}

func (f *fakeObjectStore) CopyObject(ctx context.Context, srcBucket, srcKey, srcVersionID, dstBucket, dstKey string) (api.ObjectMeta, error) {
	f.mu.Lock()
	data, ok := f.objects[srcBucket+"/"+srcKey]
	if ok {
		f.objects[dstBucket+"/"+dstKey] = data
	}
	f.mu.Unlock()
	if !ok {
		return api.ObjectMeta{}, io.EOF
	}
	return api.ObjectMeta{Bucket: dstBucket, Key: dstKey, ETag: "etag-fake", VersionID: "v1", Size: int64(len(data))}, nil
}

func (f *fakeObjectStore) InitiateMultipart(ctx context.Context, bucket, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextVers++
	uploadID := fmt.Sprintf("upload-%d", f.nextVers)
	f.uploads[uploadID] = map[int][]byte{}
	return uploadID, nil
}

func (f *fakeObjectStore) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	parts, ok := f.uploads[uploadID]
	if !ok {
		return "", fmt.Errorf("upload not found")
	}
	parts[partNumber] = data
	return fmt.Sprintf("part-etag-%d", partNumber), nil
}

func (f *fakeObjectStore) CompleteMultipart(ctx context.Context, bucket, key, uploadID string, parts []api.PartInfo) (api.ObjectMeta, error) {
	f.mu.Lock()
	stored, ok := f.uploads[uploadID]
	if !ok {
		f.mu.Unlock()
		return api.ObjectMeta{}, fmt.Errorf("upload not found")
	}
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(stored[p.PartNumber])
	}
	delete(f.uploads, uploadID)
	f.objects[bucket+"/"+key] = buf.Bytes()
	f.mu.Unlock()
	return api.ObjectMeta{Bucket: bucket, Key: key, ETag: "etag-fake", VersionID: "v1", Size: int64(buf.Len())}, nil
}

func (f *fakeObjectStore) AbortMultipart(ctx context.Context, bucket, key, uploadID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.uploads[uploadID]; !ok {
		return fmt.Errorf("upload not found")
	}
	delete(f.uploads, uploadID)
	return nil
}

var _ api.ObjectService = (*fakeObjectStore)(nil)

// fakeAuth accepts exactly one hardcoded token, for testing the
// auth-required-when-configured / auth-optional-when-absent behavior.
type fakeAuth struct {
	validToken string
	// principal is returned on a successful Authenticate; if zero-valued,
	// defaults to Principal{Subject: "test-user"} for existing callers
	// that don't care about the identity, only that auth succeeded.
	principal api.Principal
}

func (f *fakeAuth) Name() string { return "auth-fake" }
func (f *fakeAuth) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	tok, _ := credential.(string)
	if tok != f.validToken {
		return api.Principal{}, errUnauthorized
	}
	if f.principal.Subject == "" {
		return api.Principal{Subject: "test-user"}, nil
	}
	return f.principal, nil
}
func (f *fakeAuth) Authorize(ctx context.Context, p api.Principal, action, resource string) (bool, error) {
	return true, nil
}

var _ api.AuthProvider = (*fakeAuth)(nil)

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

const errUnauthorized = simpleErr("unauthorized")

// fakeRegistry/fakeKernel let us drive Plugin.Init without a real kernel.

type fakeRegistry struct {
	services map[string]any
}

func newFakeRegistry() *fakeRegistry { return &fakeRegistry{services: map[string]any{}} }

func (r *fakeRegistry) Provide(name string, svc any) error { r.services[name] = svc; return nil }
func (r *fakeRegistry) Lookup(name string) (any, bool)     { v, ok := r.services[name]; return v, ok }
func (r *fakeRegistry) MustLookup(name string) any         { return r.services[name] }

var _ api.Registry = (*fakeRegistry)(nil)

type noopEventBus struct{}

func (noopEventBus) Publish(ctx context.Context, ev api.Event)              {}
func (noopEventBus) Subscribe(topic string, h api.Handler) api.Subscription { return noopSub{} }

type noopSub struct{}

func (noopSub) Unsubscribe() {}

type fakeConfig struct{ data map[string]any }

func (c *fakeConfig) Scoped(name string) api.PluginConfig { return &fakePluginConfig{data: c.data} }

type fakePluginConfig struct{ data map[string]any }

func (c *fakePluginConfig) String(key, def string) string {
	if v, ok := c.data[key].(string); ok {
		return v
	}
	return def
}
func (c *fakePluginConfig) Int(key string, def int) int {
	if v, ok := c.data[key].(int); ok {
		return v
	}
	return def
}
func (c *fakePluginConfig) Bool(key string, def bool) bool                       { return def }
func (c *fakePluginConfig) Duration(key string, def time.Duration) time.Duration { return def }
func (c *fakePluginConfig) Raw() map[string]any                                  { return c.data }

type noopLogger struct{ t *testing.T }

func (l noopLogger) Debug(msg string, kv ...any) {}
func (l noopLogger) Info(msg string, kv ...any)  {}
func (l noopLogger) Warn(msg string, kv ...any) {
	if l.t != nil {
		l.t.Logf("WARN: %s %v", msg, kv)
	}
}
func (l noopLogger) Error(msg string, kv ...any) {
	if l.t != nil {
		l.t.Logf("ERROR: %s %v", msg, kv)
	}
}

type fakeKernel struct {
	reg *fakeRegistry
	cfg *fakeConfig
	log api.Logger
}

func (k *fakeKernel) Registry() api.Registry     { return k.reg }
func (k *fakeKernel) Events() api.EventBus       { return noopEventBus{} }
func (k *fakeKernel) Config() api.ConfigProvider { return k.cfg }
func (k *fakeKernel) Logger() api.Logger         { return k.log }

var _ api.Kernel = (*fakeKernel)(nil)

func newTestPlugin(t *testing.T, withAuth bool, withMetrics bool) (*Plugin, *fakeKV, *fakeObjectStore) {
	t.Helper()
	reg := newFakeRegistry()
	kv := newFakeKV()
	obj := newFakeObjectStore()
	reg.Provide("kv", kv)
	reg.Provide("object", obj)
	if withAuth {
		reg.Provide("auth.jwt", &fakeAuth{validToken: "good-token"})
	}
	if withMetrics {
		reg.Provide("metrics", &fakeMetricsSink{})
	}

	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, kv, obj
}

type fakeMetricsSink struct{}

func (fakeMetricsSink) Counter(name string, labels map[string]string) api.Counter {
	return fakeInstrument{}
}
func (fakeMetricsSink) Gauge(name string, labels map[string]string) api.Gauge {
	return fakeInstrument{}
}
func (fakeMetricsSink) Histogram(name string, labels map[string]string) api.Histogram {
	return fakeInstrument{}
}
func (fakeMetricsSink) Expose() ([]byte, string) {
	return []byte("# HELP fake\n"), "text/plain; version=0.0.4"
}

type fakeInstrument struct{}

func (fakeInstrument) Inc()            {}
func (fakeInstrument) Add(float64)     {}
func (fakeInstrument) Set(float64)     {}
func (fakeInstrument) Observe(float64) {}

// --- actual tests ---

func TestRoutesRegisteredExactlyOnce(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	// Calling buildMux a second time from the same plugin must also be
	// duplicate-free internally (it starts a fresh routeTable each call) —
	// the real regression guard is that WITHIN one routeTable, every
	// pattern is asserted unique via routeTable.handle's seen-map, which
	// this test exercises implicitly by succeeding at all. To make the
	// regression explicit, construct a routeTable directly and register
	// one path twice.
	rt := newRouteTable()
	rt.handle("GET /api/kv/{key}", func(w http.ResponseWriter, r *http.Request) {})
	rt.handle("GET /api/kv/{key}", func(w http.ResponseWriter, r *http.Request) {})
	if rt.err() == nil {
		t.Fatal("expected duplicate route registration to produce an error")
	}

	if len(t1.patterns()) == 0 {
		t.Fatal("expected at least one route registered")
	}
}

func TestKVRoundTrip(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(rt.mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/kv/foo", strings.NewReader("bar"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT failed: err=%v status=%v", err, resp)
	}

	resp, err = http.Get(srv.URL + "/api/kv/foo")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET failed: err=%v status=%v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "bar" {
		t.Fatalf("expected body 'bar', got %q", body)
	}

	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/api/kv/foo", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE failed: err=%v status=%v", err, resp)
	}

	resp, _ = http.Get(srv.URL + "/api/kv/foo")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestObjectRoundTrip(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(rt.mux)
	defer srv.Close()

	resp, err := http.DefaultClient.Do(mustReq(http.MethodPut, srv.URL+"/api/buckets/b1", nil))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create bucket failed: err=%v status=%v", err, resp)
	}

	resp, err = http.DefaultClient.Do(mustReq(http.MethodPut, srv.URL+"/api/buckets/b1/objects/o1", strings.NewReader("hello")))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("put object failed: err=%v status=%v", err, resp)
	}

	resp, err = http.Get(srv.URL + "/api/buckets/b1/objects/o1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get object failed: err=%v status=%v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("expected 'hello', got %q", body)
	}

	resp, err = http.Get(srv.URL + "/api/buckets/b1/objects")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("list objects failed: err=%v status=%v", err, resp)
	}

	resp, err = http.DefaultClient.Do(mustReq(http.MethodDelete, srv.URL+"/api/buckets/b1/objects/o1", nil))
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete object failed: err=%v status=%v", err, resp)
	}
}

func TestAuthRequiredWhenConfiguredAllowedWhenAbsent(t *testing.T) {
	// With an auth provider registered, requests without a valid bearer
	// token must be rejected.
	pAuth, _, _ := newTestPlugin(t, true, false)
	rtAuth, err := pAuth.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srvAuth := httptest.NewServer(rtAuth.mux)
	defer srvAuth.Close()

	resp, _ := http.Get(srvAuth.URL + "/api/kv/foo")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srvAuth.URL+"/api/kv/foo", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNotFound {
		// 404 because "foo" was never Put in this sub-test — the point is
		// it's NOT 401, i.e. auth passed.
		t.Fatalf("expected auth to pass (404, not 401), got err=%v status=%v", err, resp)
	}

	// With no auth provider registered, requests are allowed through
	// unauthenticated.
	pNoAuth, _, _ := newTestPlugin(t, false, false)
	rtNoAuth, err := pNoAuth.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srvNoAuth := httptest.NewServer(rtNoAuth.mux)
	defer srvNoAuth.Close()

	resp, err = http.Get(srvNoAuth.URL + "/api/kv/foo")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected unauthenticated request to reach the handler (404, not 401), got err=%v status=%v", err, resp)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, true)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(rt.mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: err=%v status=%v", err, resp)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("unexpected content type: %q", ct)
	}
}

func mustReq(method, url string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	return req
}

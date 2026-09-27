package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestHealthz_AlwaysOKWhenServing(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	t1.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
}

// unhealthyMetricsSink implements both api.MetricsSink and healthChecker,
// reporting itself unhealthy, so /readyz has something real to catch.
type unhealthyMetricsSink struct{ fakeMetricsSink }

func (unhealthyMetricsSink) Health() api.Health {
	return api.Health{Status: "down", Detail: "simulated failure for TestReadyz_ReportsUnhealthyDependency"}
}

func TestReadyz_OKWhenAllDependenciesHealthy(t *testing.T) {
	// fakeKV/fakeObjectStore/fakeAuth in this package's other tests don't
	// implement Health(), so dependencyHealth() simply won't include them
	// — readyz must still report 200 (no unhealthy entries is success).
	p, _, _ := newTestPlugin(t, false, false)
	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	t1.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadyz_ReportsUnhealthyDependency(t *testing.T) {
	reg := newFakeRegistry()
	reg.Provide("kv", newFakeKV())
	reg.Provide("object", newFakeObjectStore())
	reg.Provide("metrics", unhealthyMetricsSink{})
	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	t1.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	unhealthy, ok := body["unhealthy"].(map[string]any)
	if !ok {
		t.Fatalf("expected an \"unhealthy\" object in response, got %v", body)
	}
	if _, ok := unhealthy["metrics"]; !ok {
		t.Fatalf("expected \"metrics\" listed as unhealthy, got %v", unhealthy)
	}
}

func TestRateLimit_ExceedingRPSGets429WithRetryAfter(t *testing.T) {
	reg := newFakeRegistry()
	reg.Provide("kv", newFakeKV())
	reg.Provide("object", newFakeObjectStore())
	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{
		"rate_limit_rps":   1,
		"rate_limit_burst": 1,
	}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if p.rateLimiter == nil {
		t.Fatalf("expected rateLimiter to be configured")
	}

	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	doReq := func() int {
		req := httptest.NewRequest("GET", "/api/kv/somekey", nil)
		req.RemoteAddr = "203.0.113.5:12345"
		rec := httptest.NewRecorder()
		t1.mux.ServeHTTP(rec, req)
		return rec.Code
	}

	// Burst of 1: first request consumes the sole token and should not be
	// 429 (it may 404 if the key doesn't exist — that's fine, we only care
	// about rate-limit status here); the immediate second request must be
	// 429 with Retry-After.
	first := doReq()
	if first == http.StatusTooManyRequests {
		t.Fatalf("first request unexpectedly rate-limited")
	}

	req := httptest.NewRequest("GET", "/api/kv/somekey", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	rec := httptest.NewRecorder()
	t1.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second immediate request status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429 response")
	}

	// A different client IP must have its own independent bucket.
	req2 := httptest.NewRequest("GET", "/api/kv/somekey", nil)
	req2.RemoteAddr = "198.51.100.9:9999"
	rec2 := httptest.NewRecorder()
	t1.mux.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusTooManyRequests {
		t.Fatalf("a different client IP was rate-limited by another client's bucket")
	}

	// After waiting past the refill window, the original client should be
	// allowed again.
	time.Sleep(1100 * time.Millisecond)
	if code := doReq(); code == http.StatusTooManyRequests {
		t.Fatalf("request after refill window still rate-limited")
	}
}

func TestRateLimit_DisabledByDefault(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	if p.rateLimiter != nil {
		t.Fatalf("expected rate limiting disabled (nil limiter) when rate_limit_rps is unset")
	}
}

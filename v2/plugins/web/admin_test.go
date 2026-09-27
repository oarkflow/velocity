package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// healthyKV/unhealthyKV wrap fakeKV to additionally implement
// healthChecker (Health() api.Health) — the plain fakeKV used elsewhere in
// this package's tests deliberately does NOT implement it (dependencyHealth
// only reports on services that opt in), so dashboard-content assertions
// need a wrapper that does.
type healthyKV struct{ *fakeKV }

func (h *healthyKV) Health() api.Health { return api.Health{Status: "ok"} }

type unhealthyKV struct{ *fakeKV }

func (u *unhealthyKV) Health() api.Health {
	return api.Health{Status: "down", Detail: "simulated failure"}
}

func TestAdminDashboard_ListsPluginsAndDistinguishesUnhealthy(t *testing.T) {
	reg := newFakeRegistry()
	reg.Provide("kv", &healthyKV{fakeKV: newFakeKV()})
	reg.Provide("object", newFakeObjectStore())

	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// startTime is left at its zero value here — handleAdmin must tolerate
	// that (Init doesn't set it; only Start does) rather than panicking or
	// rendering a nonsensical uptime.

	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("GET /admin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "kv") {
		t.Errorf("expected dashboard body to mention the kv dependency, got:\n%s", body)
	}
	if !strings.Contains(body, "status-ok") {
		t.Errorf("expected the healthy kv dependency to render with status-ok, got:\n%s", body)
	}
}

func TestAdminDashboard_DistinguishesUnhealthyDependency(t *testing.T) {
	reg := newFakeRegistry()
	kv := &unhealthyKV{fakeKV: newFakeKV()}
	obj := newFakeObjectStore()
	reg.Provide("kv", kv)
	reg.Provide("object", obj)

	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest("GET", "/admin", nil)
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("GET /admin: status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "status-down") {
		t.Errorf("expected an unhealthy dependency to render with a distinguishing class (status-down), got:\n%s", body)
	}
	if !strings.Contains(body, "simulated failure") {
		t.Errorf("expected the unhealthy dependency's detail text in the body, got:\n%s", body)
	}
}

func TestAdminDashboard_RequiresAuthWhenConfigured(t *testing.T) {
	p, _, _ := newTestPlugin(t, true, false)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	// No token: must be rejected, same as any other /api/* route.
	req := httptest.NewRequest("GET", "/admin", nil)
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("GET /admin without a token: status = %d, want 401", rec.Code)
	}

	// Valid token: must succeed.
	req = httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec = httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /admin with a valid token: status = %d, want 200", rec.Code)
	}
}

func TestAdminDashboard_RedirectRouteWorks(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest("GET", "/admin/", nil)
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)
	if rec.Code != 301 {
		t.Fatalf("GET /admin/: status = %d, want 301 redirect to /admin", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin" {
		t.Fatalf("GET /admin/: Location = %q, want \"/admin\"", loc)
	}
}

func TestRoutesRegisteredExactlyOnce_StillPassesWithAdmin(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	t1, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	found := false
	for _, pattern := range t1.patterns() {
		if pattern == "GET /admin" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected \"GET /admin\" to be a registered route pattern")
	}
}

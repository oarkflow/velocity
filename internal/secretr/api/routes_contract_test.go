package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIRouteContractSnapshot(t *testing.T) {
	s := NewServer(Config{Address: ":0"})

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/health"},
		{http.MethodGet, "/ready"},
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodPost, "/api/v1/auth/refresh"},
		{http.MethodGet, "/api/v1/secrets"},
		{http.MethodPost, "/api/v1/secrets"},
		{http.MethodGet, "/api/v1/secrets/name"},
		{http.MethodGet, "/api/v1/identities"},
		{http.MethodGet, "/api/v1/identities/id"},
		{http.MethodGet, "/api/v1/audit"},
		{http.MethodGet, "/api/v1/audit/export"},
		{http.MethodPost, "/api/v1/cicd/auth"},
		{http.MethodGet, "/api/v1/files"},
		{http.MethodPost, "/api/v1/files"},
		{http.MethodGet, "/api/v1/files/name"},
		{http.MethodGet, "/api/v1/monitoring/dashboard"},
		{http.MethodGet, "/api/v1/monitoring/events"},
		{http.MethodGet, "/api/v1/monitoring/stream"},
		{http.MethodGet, "/api/v1/alerts"},
		{http.MethodGet, "/api/v1/alerts/id"},
		{http.MethodPost, "/api/v1/alerts/id/acknowledge"},
		{http.MethodPost, "/api/v1/alerts/id/resolve"},
		{http.MethodGet, "/api/v1/alerts/rules"},
		{http.MethodGet, "/api/v1/alerts/notifiers"},
		{http.MethodPost, "/api/v1/commands/secret/list"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("route missing for %s %s", tc.method, tc.path)
		}
	}
}

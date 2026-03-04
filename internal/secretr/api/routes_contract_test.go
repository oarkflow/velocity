package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIRouteContractSnapshot(t *testing.T) {
	s := NewServer(Config{Address: ":0"})

	for _, tc := range RouteMethodContract() {
		req := httptest.NewRequest(tc.Method, tc.Path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("route missing for %s %s", tc.Method, tc.Path)
		}
	}
}

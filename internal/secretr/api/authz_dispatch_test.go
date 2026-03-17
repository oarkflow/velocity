package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

func TestCommandDispatchUnknownSpecFailsClosed(t *testing.T) {
	s := NewServer(Config{Address: ":0"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/commands/nonexistent/operation", nil)
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown dispatch spec, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if body["error"] != types.ErrCodeAuthzSpecMissing {
		t.Fatalf("expected %q, got %q", types.ErrCodeAuthzSpecMissing, body["error"])
	}
}

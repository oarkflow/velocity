package web

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oarkflow/velocity"
)

func TestComplianceAPIRoutes(t *testing.T) {
	srv, db := newPentestServer(t)
	userToken := signToken(t, db.JWTSecret(), jwt.MapClaims{
		"username": "reviewer",
		"role":     "user",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})
	adminToken := signToken(t, db.JWTSecret(), jwt.MapClaims{
		"username": "admin",
		"role":     "admin",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})

	status, body := request(t, srv, "GET", "/api/v1/system/health", "", nil, "")
	if status != 401 {
		t.Fatalf("expected unauthenticated health to be rejected, got status=%d body=%s", status, body)
	}

	tag := map[string]any{
		"path":           "evidence/access-review.pdf",
		"frameworks":     []string{"SOC2"},
		"data_class":     "confidential",
		"owner":          "security",
		"retention_days": 365,
		"encryption_req": true,
	}
	raw, _ := json.Marshal(tag)
	status, body = request(t, srv, "POST", "/api/v1/compliance/tags", userToken, bytes.NewReader(raw), "application/json")
	if status != 403 {
		t.Fatalf("expected non-admin tag creation to be forbidden, got status=%d body=%s", status, body)
	}

	status, body = request(t, srv, "POST", "/api/v1/compliance/tags", adminToken, bytes.NewReader(raw), "application/json")
	if status != 201 || !strings.Contains(body, "access-review.pdf") {
		t.Fatalf("create tag status=%d body=%s", status, body)
	}
	status, body = request(t, srv, "GET", "/api/v1/compliance/tags", userToken, nil, "")
	if status != 200 || !strings.Contains(body, "SOC2") {
		t.Fatalf("list tags status=%d body=%s", status, body)
	}
	status, body = request(t, srv, "GET", "/api/v1/compliance/tags/evidence%2Faccess-review.pdf", userToken, nil, "")
	if status != 200 || !strings.Contains(body, "access-review.pdf") {
		t.Fatalf("get resource tags status=%d body=%s", status, body)
	}

	if err := db.Backup(velocity.BackupOptions{OutputPath: filepath.Join(t.TempDir(), "backup.json"), User: "admin"}); err != nil {
		t.Fatalf("create audit record: %v", err)
	}
	status, body = request(t, srv, "GET", "/api/v1/compliance/audit?operation=backup&limit=5", userToken, nil, "")
	if status != 200 || !strings.Contains(body, `"operation":"backup"`) {
		t.Fatalf("audit trail status=%d body=%s", status, body)
	}

	policy := map[string]any{
		"policy_id":       "policy-test",
		"data_type":       "confidential",
		"retention_days":  30,
		"deletion_method": "archive",
	}
	raw, _ = json.Marshal(policy)
	status, body = request(t, srv, "POST", "/api/v1/compliance/retention/policies", userToken, bytes.NewReader(raw), "application/json")
	if status != 403 {
		t.Fatalf("expected non-admin retention creation to be forbidden, got status=%d body=%s", status, body)
	}
	status, body = request(t, srv, "POST", "/api/v1/compliance/retention/policies", adminToken, bytes.NewReader(raw), "application/json")
	if status != 201 || !strings.Contains(body, "policy-test") {
		t.Fatalf("create retention policy status=%d body=%s", status, body)
	}

	hold := map[string]any{"hold_id": "hold-test", "reason": "open audit", "case_number": "CASE-001"}
	raw, _ = json.Marshal(hold)
	status, body = request(t, srv, "POST", "/api/v1/compliance/retention/policies/policy-test/legal-holds", adminToken, bytes.NewReader(raw), "application/json")
	if status != 201 {
		t.Fatalf("add legal hold status=%d body=%s", status, body)
	}
	status, body = request(t, srv, "POST", "/api/v1/compliance/retention/policies/policy-test/legal-holds/hold-test/release", adminToken, nil, "")
	if status != 200 {
		t.Fatalf("release legal hold status=%d body=%s", status, body)
	}
	status, body = request(t, srv, "GET", "/api/v1/compliance/retention/policies", userToken, nil, "")
	if status != 200 || !strings.Contains(body, "policy-test") || !strings.Contains(body, `"active":false`) {
		t.Fatalf("list retention policies status=%d body=%s", status, body)
	}
}

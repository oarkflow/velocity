package middleware

import (
	"context"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// MockSessionProvider for testing
type MockSessionProvider struct {
	Session  *types.Session
	Identity *types.Identity
	Err      error
}

func (m *MockSessionProvider) GetCurrentSession(ctx context.Context) (*types.Session, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Session, nil
}

func (m *MockSessionProvider) GetIdentity(ctx context.Context, id types.ID) (*types.Identity, error) {
	return m.Identity, nil
}

func TestScopeSet_Has(t *testing.T) {
	scopes := types.NewScopeSet(
		types.ScopeSecretRead,
		types.ScopeSecretUpdate,
		types.ScopeSecretList,
	)

	if !scopes.Has(types.ScopeSecretRead) {
		t.Error("ScopeSet should have ScopeSecretRead")
	}

	if !scopes.Has(types.ScopeSecretUpdate) {
		t.Error("ScopeSet should have ScopeSecretUpdate")
	}

	if scopes.Has(types.ScopeSecretDelete) {
		t.Error("ScopeSet should not have ScopeSecretDelete")
	}
}

func TestScopeSet_AdminHasAll(t *testing.T) {
	scopes := types.NewScopeSet(types.ScopeAdminAll)

	// Admin scope should have all scopes
	if !scopes.Has(types.ScopeSecretRead) {
		t.Error("Admin scope should have ScopeSecretRead")
	}

	if !scopes.Has(types.ScopeKeyGenerate) {
		t.Error("Admin scope should have ScopeKeyGenerate")
	}

	if !scopes.Has(types.ScopeIncidentDeclare) {
		t.Error("Admin scope should have ScopeIncidentDeclare")
	}
}

func TestScopeSet_HasAll(t *testing.T) {
	scopes := types.NewScopeSet(
		types.ScopeSecretRead,
		types.ScopeSecretUpdate,
		types.ScopeSecretList,
	)

	if !scopes.HasAll(types.ScopeSecretRead, types.ScopeSecretUpdate) {
		t.Error("ScopeSet should have all specified scopes")
	}

	if scopes.HasAll(types.ScopeSecretRead, types.ScopeSecretDelete) {
		t.Error("ScopeSet should not have all specified scopes (missing delete)")
	}
}

func TestScopeSet_HasAny(t *testing.T) {
	scopes := types.NewScopeSet(types.ScopeSecretRead)

	if !scopes.HasAny(types.ScopeSecretRead, types.ScopeSecretUpdate) {
		t.Error("ScopeSet should have at least one of the specified scopes")
	}

	if scopes.HasAny(types.ScopeKeyGenerate, types.ScopeFileUpload) {
		t.Error("ScopeSet should not have any of the specified scopes")
	}
}

func TestScopeSet_Add(t *testing.T) {
	scopes := types.NewScopeSet()

	if scopes.Has(types.ScopeSecretRead) {
		t.Error("Empty ScopeSet should not have ScopeSecretRead")
	}

	scopes.Add(types.ScopeSecretRead)

	if !scopes.Has(types.ScopeSecretRead) {
		t.Error("ScopeSet should have ScopeSecretRead after Add")
	}
}

func TestScopeSet_Remove(t *testing.T) {
	scopes := types.NewScopeSet(types.ScopeSecretRead, types.ScopeSecretUpdate)

	scopes.Remove(types.ScopeSecretRead)

	if scopes.Has(types.ScopeSecretRead) {
		t.Error("ScopeSet should not have ScopeSecretRead after Remove")
	}

	if !scopes.Has(types.ScopeSecretUpdate) {
		t.Error("ScopeSet should still have ScopeSecretUpdate")
	}
}

func TestGetRequiredScopes(t *testing.T) {
	tests := []struct {
		command string
		want    []types.Scope
	}{
		{"secret create", []types.Scope{types.ScopeSecretCreate}},
		{"secret get", []types.Scope{types.ScopeSecretRead}},
		{"key generate", []types.Scope{types.ScopeKeyGenerate}},
		{"file upload", []types.Scope{types.ScopeFileUpload}},
		{"audit query", []types.Scope{types.ScopeAuditQuery}},
		{"unknown command", nil},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := GetRequiredScopes(tt.command)
			if tt.want == nil && got != nil {
				t.Errorf("GetRequiredScopes(%q) = %v, want nil", tt.command, got)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("GetRequiredScopes(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := types.Now()

	// Active session
	activeSession := &types.Session{
		ExpiresAt: types.Timestamp(int64(now) + 3600*1e9), // 1 hour from now
		Status:    types.StatusActive,
	}

	if activeSession.IsExpired() {
		t.Error("Session should not be expired")
	}

	// Expired session
	expiredSession := &types.Session{
		ExpiresAt: types.Timestamp(int64(now) - 3600*1e9), // 1 hour ago
		Status:    types.StatusActive,
	}

	if !expiredSession.IsExpired() {
		t.Error("Session should be expired")
	}
}

func TestSession_IsActive(t *testing.T) {
	now := types.Now()

	// Active session
	activeSession := &types.Session{
		ExpiresAt: types.Timestamp(int64(now) + 3600*1e9),
		Status:    types.StatusActive,
	}

	if !activeSession.IsActive() {
		t.Error("Session should be active")
	}

	// Revoked session
	revokedSession := &types.Session{
		ExpiresAt: types.Timestamp(int64(now) + 3600*1e9),
		Status:    types.StatusRevoked,
	}

	if revokedSession.IsActive() {
		t.Error("Revoked session should not be active")
	}
}

func TestCommandPermissions_Coverage(t *testing.T) {
	// Verify all major command categories have permissions defined
	categories := []string{
		"auth", "identity", "device", "session", "key",
		"secret", "file", "access", "role", "policy",
		"audit", "share", "backup", "org", "incident",
	}

	for _, cat := range categories {
		found := false
		for cmd := range CommandPermissions {
			if len(cmd) >= len(cat) && cmd[:len(cat)] == cat {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("No permissions defined for category: %s", cat)
		}
	}
}

func TestContextKeys(t *testing.T) {
	ctx := context.Background()

	// Test session context
	session := &types.Session{ID: "test-session"}
	ctx = context.WithValue(ctx, SessionContextKey, session)

	retrieved := GetSession(ctx)
	if retrieved == nil {
		t.Error("Should retrieve session from context")
	}
	if retrieved.ID != "test-session" {
		t.Error("Retrieved session ID mismatch")
	}

	// Test scopes context
	scopes := types.NewScopeSet(types.ScopeSecretRead)
	ctx = context.WithValue(ctx, ScopesContextKey, scopes)

	if !HasScope(ctx, types.ScopeSecretRead) {
		t.Error("Should have ScopeSecretRead in context")
	}
	if HasScope(ctx, types.ScopeSecretUpdate) {
		t.Error("Should not have ScopeSecretUpdate in context")
	}
}

func TestRequireAuthenticated_WithNilSessionProvider(t *testing.T) {
	gate := NewPermissionGate(nil, nil)
	before := gate.RequireAuthenticated()
	ctx := context.Background()
	_, err := before(ctx, &cli.Command{Name: "status"})
	if err != nil {
		t.Fatalf("expected nil error with nil session provider, got %v", err)
	}
}

package access

import (
	"context"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	store, err := storage.NewStore(storage.Config{
		Path:          t.TempDir(),
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewManager(ManagerConfig{Store: store})
}

func TestCheck_DeniesWhenNoGrantExists(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.Check(context.Background(), types.ID("user-1"), types.ID("secret-1"), []types.Scope{types.ScopeSecretRead})
	if err == nil {
		t.Fatal("expected deny when no grant exists")
	}
	if err != ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied, got: %v", err)
	}
}

func TestCheck_DeniesWhenGrantExistsButScopesDoNotMatch(t *testing.T) {
	mgr := newTestManager(t)
	_, err := mgr.Grant(context.Background(), GrantOptions{
		GrantorID:    types.ID("admin"),
		GranteeID:    types.ID("user-1"),
		ResourceID:   types.ID("secret-1"),
		ResourceType: "secret",
		Scopes:       []types.Scope{types.ScopeSecretRead},
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	err = mgr.Check(context.Background(), types.ID("user-1"), types.ID("secret-1"), []types.Scope{types.ScopeSecretUpdate})
	if err == nil {
		t.Fatal("expected deny when grant exists but required scopes do not match")
	}
	if err != ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied, got: %v", err)
	}
}

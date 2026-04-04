package authz

import (
	"net/http"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

func TestResolveCLI_ListScope_NoResourceIDFallback(t *testing.T) {
	resolver := NewDefaultResourceResolver()
	cmd := &cli.Command{}
	_, rid, _, _ := resolver.ResolveCLI(cmd, &types.Session{}, "secret list", CommandAuthSpec{
		Path:           "secret list",
		ResourceType:   "secret",
		RequireACL:     true,
		RequiredScopes: []types.Scope{types.ScopeSecretList},
	})
	if rid != "" {
		t.Fatalf("expected empty resource id for list scope, got %q", rid)
	}
}

func TestResolveAPI_ListScope_NoResourceIDFallback(t *testing.T) {
	resolver := NewDefaultResourceResolver()
	r, _ := http.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	_, rid, _, _ := resolver.ResolveAPI(r, &types.Session{}, APIRouteAuthSpec{
		Method:         http.MethodGet,
		Pattern:        "/api/v1/secrets",
		ResourceType:   "secret",
		RequireACL:     true,
		RequiredScopes: []types.Scope{types.ScopeSecretList},
	})
	if rid != "" {
		t.Fatalf("expected empty resource id for list scope, got %q", rid)
	}
}

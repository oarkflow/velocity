package api

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/authz"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

func TestResolveAPIResourceID_PathAndQueryAndBody(t *testing.T) {
	resolver := authz.NewDefaultResourceResolver()
	session := &types.Session{}
	// path id
	r1, _ := http.NewRequest(http.MethodGet, "/api/v1/secrets/secret-1", nil)
	_, got, _, _ := resolver.ResolveAPI(r1, session, authz.APIRouteAuthSpec{Method: http.MethodGet, Pattern: "/api/v1/secrets/", ResourceType: "secret", RequireACL: true})
	if got != "secret-1" {
		t.Fatalf("expected path id, got %q", got)
	}

	// query id
	r2, _ := http.NewRequest(http.MethodGet, "/api/v1/secrets?id=secret-2", nil)
	_, got, _, _ = resolver.ResolveAPI(r2, session, authz.APIRouteAuthSpec{Method: http.MethodGet, Pattern: "/api/v1/secrets", ResourceType: "secret", RequireACL: true})
	if got != "secret-2" {
		t.Fatalf("expected query id, got %q", got)
	}

	// body id
	r3, _ := http.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewBufferString(`{"name":"secret-3"}`))
	_, got, _, _ = resolver.ResolveAPI(r3, session, authz.APIRouteAuthSpec{Method: http.MethodPost, Pattern: "/api/v1/secrets", ResourceType: "secret", RequireACL: true})
	if got != "secret-3" {
		t.Fatalf("expected body id, got %q", got)
	}
}

func TestResolveAPIResourceID_CommandDispatch(t *testing.T) {
	resolver := authz.NewDefaultResourceResolver()
	session := &types.Session{}
	r, _ := http.NewRequest(http.MethodPost, "/api/v1/commands/secret/list", nil)
	_, got, _, _ := resolver.ResolveAPI(r, session, authz.APIRouteAuthSpec{Method: http.MethodPost, Pattern: "/api/v1/commands/", ResourceType: "secret", RequireACL: true})
	if got != "secret list" {
		t.Fatalf("expected command path as resource id, got %q", got)
	}
}

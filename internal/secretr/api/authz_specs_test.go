package api

import (
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/authz"
)

func TestAPIRoutesHaveAuthzSpecs(t *testing.T) {
	s := NewServer(Config{Address: ":0"})
	specs := s.RouteAuthSpecs()
	contract := RouteMethodContract()
	for _, tc := range contract {
		spec, ok := authz.ResolveAPIRouteSpec(tc.Method, tc.Path, specs)
		if !ok {
			t.Fatalf("missing authz spec for %s %s", tc.Method, tc.Path)
		}
		if !spec.AllowUnauth && len(spec.RequiredScopes) == 0 {
			t.Fatalf("missing required scopes in authz spec for %s %s", tc.Method, tc.Path)
		}
	}

	for _, spec := range specs {
		matched := false
		for _, tc := range contract {
			if _, ok := authz.ResolveAPIRouteSpec(tc.Method, tc.Path, []authz.APIRouteAuthSpec{spec}); ok {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("orphan authz route spec not represented in API contract: %s %s", spec.Method, spec.Pattern)
		}
	}
}

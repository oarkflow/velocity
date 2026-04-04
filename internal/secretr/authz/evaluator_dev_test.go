//go:build secretr_dev

package authz

import (
	"context"
	"errors"
	"testing"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type devFailIfCalledACL struct{}

func (devFailIfCalledACL) Check(ctx context.Context, identityID types.ID, resourceID types.ID, requiredScopes []types.Scope) error {
	return errors.New("acl should be bypassed in secretr_dev")
}

func TestAuthorize_DevBuild_BypassesACL(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{
		"secret": {
			FeatureSlug: "secret",
			Enabled:     true,
			Scopes: map[string]licclient.ScopeGrant{
				"secret:update": {ScopeSlug: "secret:update", Permission: licclient.ScopePermissionAllow},
			},
		},
	}}}
	a := NewAuthorizer(staticProvider{lic: lic}, devFailIfCalledACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{
		Session:        mkSession(types.ScopeSecretUpdate),
		RequiredScopes: []types.Scope{types.ScopeSecretUpdate},
		RequireACL:     true,
		ResourceID:     "ENV_SECRET",
		ResourceType:   "secret",
	})
	if err != nil {
		t.Fatalf("expected ACL bypass in dev build, got: %v", err)
	}
}

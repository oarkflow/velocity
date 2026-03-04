package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type staticProvider struct{ lic *licclient.LicenseData }

func (s staticProvider) GetLicenseData(ctx context.Context, actorID types.ID) (*licclient.LicenseData, error) {
	return s.lic, nil
}

type allowACL struct{}

func (allowACL) Check(ctx context.Context, identityID types.ID, resourceID types.ID, requiredScopes []types.Scope) error {
	return nil
}

type denyACL struct{}

func (denyACL) Check(ctx context.Context, identityID types.ID, resourceID types.ID, requiredScopes []types.Scope) error {
	return types.NewError(types.ErrCodeACLDenied, "acl deny")
}

type denyPolicy struct{}

func (denyPolicy) Evaluate(ctx context.Context, actorID types.ID, resourceID types.ID, resourceType string, action string, metadata map[string]any) (bool, string, error) {
	return false, "policy denied", nil
}

func mkSession(scopes ...types.Scope) *types.Session {
	return &types.Session{
		ID:         "s1",
		IdentityID: "u1",
		Status:     types.StatusActive,
		CreatedAt:  types.Now(),
		ExpiresAt:  types.Timestamp(time.Now().Add(24 * time.Hour).UnixNano()),
		Scopes:     types.NewScopeSet(scopes...),
		ScopeList:  scopes,
	}
}

func TestAuthorize_DenyByRBAC(t *testing.T) {
	a := NewAuthorizer(staticProvider{lic: &licclient.LicenseData{}}, allowACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretDelete}})
	if err == nil {
		t.Fatal("expected rbac deny")
	}
}

func TestAuthorize_DenyWhenLicenseMissing(t *testing.T) {
	a := NewAuthorizer(staticProvider{lic: nil}, allowACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretRead}})
	var te *types.Error
	if err == nil || !errors.As(err, &te) || te.Code != types.ErrCodeEntitlementScopeRequired {
		t.Fatalf("expected entitlement scope required for missing license, got %v", err)
	}
}

func TestAuthorize_DenyByEntitlementMissing(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{}}}
	a := NewAuthorizer(staticProvider{lic: lic}, allowACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretRead}})
	var te *types.Error
	if err == nil || !errors.As(err, &te) || te.Code != types.ErrCodeEntitlementScopeRequired {
		t.Fatalf("expected entitlement scope required, got %v", err)
	}
}

func TestAuthorize_DenyByEntitlementDeny(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{"secret": {FeatureSlug: "secret", Enabled: true, Scopes: map[string]licclient.ScopeGrant{"secret:read": {ScopeSlug: "secret:read", Permission: licclient.ScopePermissionDeny}}}}}}
	a := NewAuthorizer(staticProvider{lic: lic}, allowACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretRead}})
	var te *types.Error
	if err == nil || !errors.As(err, &te) || te.Code != types.ErrCodeEntitlementDenied {
		t.Fatalf("expected entitlement denied, got %v", err)
	}
}

func TestAuthorize_DenyByACL(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{"secret": {FeatureSlug: "secret", Enabled: true, Scopes: map[string]licclient.ScopeGrant{"secret:read": {ScopeSlug: "secret:read", Permission: licclient.ScopePermissionAllow}}}}}}
	a := NewAuthorizer(staticProvider{lic: lic}, denyACL{}, nil)
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretRead}, RequireACL: true, ResourceID: "secret1"})
	var te *types.Error
	if err == nil || !errors.As(err, &te) || te.Code != types.ErrCodeACLDenied {
		t.Fatalf("expected acl denied, got %v", err)
	}
}

func TestAuthorize_DenyByPolicy(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{"secret": {FeatureSlug: "secret", Enabled: true, Scopes: map[string]licclient.ScopeGrant{"secret:read": {ScopeSlug: "secret:read", Permission: licclient.ScopePermissionAllow}}}}}}
	a := NewAuthorizer(staticProvider{lic: lic}, allowACL{}, nil)
	a.SetPolicyChecker(denyPolicy{})
	_, err := a.Authorize(context.Background(), Request{Session: mkSession(types.ScopeSecretRead), RequiredScopes: []types.Scope{types.ScopeSecretRead}, RequireACL: true, ResourceID: "secret1", ResourceType: "secret"})
	var te *types.Error
	if err == nil || !errors.As(err, &te) || te.Code != types.ErrCodePolicy {
		t.Fatalf("expected policy denied, got %v", err)
	}
}

func TestAuthorize_LimitWindowAndConcurrency(t *testing.T) {
	lic := &licclient.LicenseData{Entitlements: &licclient.LicenseEntitlements{Features: map[string]licclient.FeatureGrant{
		"secret": {
			FeatureSlug: "secret",
			Enabled:     true,
			Scopes: map[string]licclient.ScopeGrant{
				"secret:read": {
					ScopeSlug:  "secret:read",
					Permission: licclient.ScopePermissionLimit,
					Limit:      2,
					Restrictions: []licclient.ScopeRestriction{
						{Type: licclient.UsageRestrictionUser, Limit: 2, WindowSeconds: 1},
					},
				},
			},
		},
	}}}
	a := NewAuthorizer(staticProvider{lic: lic}, allowACL{}, nil)
	req := Request{
		Session:        mkSession(types.ScopeSecretRead),
		ActorID:        "u1",
		RequiredScopes: []types.Scope{types.ScopeSecretRead},
		UsageContext:   licclient.UsageContext{SubjectType: licclient.SubjectTypeUser, SubjectID: "u1", Amount: 1},
	}
	if _, err := a.Authorize(context.Background(), req); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	if _, err := a.Authorize(context.Background(), req); err != nil {
		t.Fatalf("second call should pass: %v", err)
	}
	if _, err := a.Authorize(context.Background(), req); err == nil {
		t.Fatal("third call should fail limit")
	}

	time.Sleep(1100 * time.Millisecond)
	if _, err := a.Authorize(context.Background(), req); err != nil {
		t.Fatalf("window reset should allow call: %v", err)
	}
}

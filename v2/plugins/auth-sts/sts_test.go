package authsts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	authldap "github.com/oarkflow/velocity/v2/plugins/auth-ldap"
	authoidc "github.com/oarkflow/velocity/v2/plugins/auth-oidc"
)

// fakeAuthenticator is a minimal api.Authenticator test double. It
// type-asserts the credential to the exact concrete type auth-sts is
// documented to construct (authoidc.Credential / authldap.Credential),
// which is what proves auth-sts's federation wiring actually constructs
// the right provider-specific type rather than something generic that
// happens to compile.
type fakeAuthenticator struct {
	name    string
	wantErr error
	handle  func(credential any) (api.Principal, error)
}

func (f *fakeAuthenticator) Name() string { return f.name }
func (f *fakeAuthenticator) Authenticate(_ context.Context, credential any) (api.Principal, error) {
	if f.wantErr != nil {
		return api.Principal{}, f.wantErr
	}
	return f.handle(credential)
}

func newTestKernel(t *testing.T) *kernel.Kernel {
	t.Helper()
	return kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{{Name: PluginName, Enabled: true}}})
}

func TestAssumeRole_DirectAndAuthenticate(t *testing.T) {
	p := New()
	if err := p.Init(context.Background(), newTestKernel(t)); err != nil {
		t.Fatalf("Init: %v", err)
	}

	res, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN:         "arn:velocity:role/admin",
		RoleSessionName: "test-session",
		UserID:          "alice",
	})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	if res.Credentials.SessionToken == "" {
		t.Fatal("expected a non-empty session token")
	}

	principal, err := p.Authenticate(context.Background(), res.Credentials.SessionToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "alice" {
		t.Fatalf("Subject = %q, want alice", principal.Subject)
	}
}

func TestAssumeRole_RequiresRoleARNAndSessionName(t *testing.T) {
	p := New()
	if err := p.Init(context.Background(), newTestKernel(t)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := p.AssumeRole(context.Background(), AssumeRoleRequest{UserID: "alice"}); err == nil {
		t.Fatal("expected error when RoleARN/RoleSessionName are missing")
	}
}

func TestRevokeSession_RejectsFurtherAuth(t *testing.T) {
	p := New()
	if err := p.Init(context.Background(), newTestKernel(t)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	res, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", UserID: "bob",
	})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	if err := p.RevokeSession(res.Credentials.SessionToken); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := p.Authenticate(context.Background(), res.Credentials.SessionToken); err == nil {
		t.Fatal("expected revoked session to be rejected")
	}
}

func TestAssumeRole_WithWebIdentityFailsWithoutOIDCWired(t *testing.T) {
	p := New() // no oidc dependency configured
	if err := p.Init(context.Background(), newTestKernel(t)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", OIDCIDToken: "whatever",
	})
	if err == nil {
		t.Fatal("expected AssumeRoleWithWebIdentity to fail loudly when auth-oidc isn't wired")
	}
}

func TestAssumeRole_WithWebIdentity_FederatesViaRealOIDCCredentialType(t *testing.T) {
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "fake-oidc", Enabled: true},
		{Name: PluginName, Enabled: true},
	}})

	fake := &fakeAuthenticator{
		name: "fake-oidc",
		handle: func(credential any) (api.Principal, error) {
			cred, ok := credential.(authoidc.Credential)
			if !ok {
				t.Fatalf("expected credential type authoidc.Credential, got %T", credential)
			}
			if cred.IDToken != "valid-token" {
				t.Fatalf("IDToken = %q, want valid-token", cred.IDToken)
			}
			return api.Principal{Subject: "federated-user", Roles: []string{"reader"}}, nil
		},
	}
	if err := k.Registry().Provide("fake-oidc", fake); err != nil {
		t.Fatalf("Provide: %v", err)
	}

	p := NewWithDeps("fake-oidc", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Set after Init: Init unconditionally (re)computes roleMappings from
	// manifest config, which would otherwise clobber a pre-Init value.
	p.roleMappings = map[string]string{"reader": "arn:velocity:policy/read-only"}

	res, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", OIDCIDToken: "valid-token",
	})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	principal, err := p.Authenticate(context.Background(), res.Credentials.SessionToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "federated-user" {
		t.Fatalf("Subject = %q, want federated-user", principal.Subject)
	}

	p.mu.RLock()
	sess := p.sess[res.Credentials.SessionToken]
	p.mu.RUnlock()
	if len(sess.PolicyARNs) != 1 || sess.PolicyARNs[0] != "arn:velocity:policy/read-only" {
		t.Fatalf("PolicyARNs = %v, want [arn:velocity:policy/read-only] (role mapping did not apply)", sess.PolicyARNs)
	}
}

func TestAssumeRole_WithWebIdentity_RejectsFailedFederatedAuth(t *testing.T) {
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "fake-oidc", Enabled: true},
		{Name: PluginName, Enabled: true},
	}})
	fake := &fakeAuthenticator{name: "fake-oidc", wantErr: errors.New("token expired")}
	if err := k.Registry().Provide("fake-oidc", fake); err != nil {
		t.Fatalf("Provide: %v", err)
	}

	p := NewWithDeps("fake-oidc", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", OIDCIDToken: "bad-token",
	}); err == nil {
		t.Fatal("expected AssumeRole to fail when the underlying OIDC Authenticate fails")
	}
}

func TestAssumeRole_WithLDAP_FederatesViaRealLDAPCredentialType(t *testing.T) {
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "fake-ldap", Enabled: true},
		{Name: PluginName, Enabled: true},
	}})
	fake := &fakeAuthenticator{
		name: "fake-ldap",
		handle: func(credential any) (api.Principal, error) {
			cred, ok := credential.(authldap.Credential)
			if !ok {
				t.Fatalf("expected credential type authldap.Credential, got %T", credential)
			}
			if cred.Username != "dave" || cred.Password != "hunter2" {
				t.Fatalf("unexpected credential: %+v", cred)
			}
			return api.Principal{Subject: "dave"}, nil
		},
	}
	if err := k.Registry().Provide("fake-ldap", fake); err != nil {
		t.Fatalf("Provide: %v", err)
	}

	p := NewWithDeps("", "fake-ldap")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	res, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", LDAPUser: "dave", LDAPPass: "hunter2",
	})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	principal, err := p.Authenticate(context.Background(), res.Credentials.SessionToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "dave" {
		t.Fatalf("Subject = %q, want dave", principal.Subject)
	}
}

func TestCleanupExpired_RemovesExpiredSessions(t *testing.T) {
	p := New()
	if err := p.Init(context.Background(), newTestKernel(t)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	res, err := p.AssumeRole(context.Background(), AssumeRoleRequest{
		RoleARN: "arn:velocity:role/x", RoleSessionName: "s", UserID: "carol", DurationSeconds: 900,
	})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	p.mu.Lock()
	p.sess[res.Credentials.SessionToken].Expiration = time.Now().Add(-time.Minute)
	p.mu.Unlock()

	if removed := p.cleanupExpired(); removed != 1 {
		t.Fatalf("cleanupExpired removed %d sessions, want 1", removed)
	}
	if _, err := p.Authenticate(context.Background(), res.Credentials.SessionToken); err == nil {
		t.Fatal("expected cleaned-up session to be rejected")
	}
}

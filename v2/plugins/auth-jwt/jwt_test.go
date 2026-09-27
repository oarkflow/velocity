package authjwt

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
)

func newTestKernel(t *testing.T, cfg map[string]any) *kernel.Kernel {
	t.Helper()
	return kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: PluginName, Enabled: true, Config: cfg},
	}})
}

// TestInit_RefusesWithoutSecret is the regression guard for v1's critical
// admin-token-forgery finding: there must be no default JWT secret.
func TestInit_RefusesWithoutSecret(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{})
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatal("expected Init to fail with no secret configured, got nil error")
	}
}

func TestInit_RefusesShortSecretWithoutDevMode(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "too-short"})
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatal("expected Init to fail with a short secret outside insecure_dev_mode, got nil error")
	}
}

func TestInit_AllowsShortSecretInDevMode(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "short", "insecure_dev_mode": true})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("expected Init to succeed in insecure_dev_mode, got %v", err)
	}
}

func TestIssueAndAuthenticate_RoundTrip(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "0123456789abcdef0123456789abcdef"})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	tok, err := p.Issue("alice", []string{"admin"}, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	principal, err := p.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "alice" {
		t.Fatalf("Subject = %q, want alice", principal.Subject)
	}

	ok, err := p.Authorize(context.Background(), principal, "any", "any")
	if err != nil || !ok {
		t.Fatalf("Authorize(admin) = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestAuthenticate_RejectsTamperedToken(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "0123456789abcdef0123456789abcdef"})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tok, err := p.Issue("alice", nil, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tampered := tok[:len(tok)-1] + "x"
	if _, err := p.Authenticate(context.Background(), tampered); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestAuthenticate_RejectsExpiredToken(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "0123456789abcdef0123456789abcdef"})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tok, err := p.Issue("alice", nil, -time.Minute) // already expired
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := p.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

// TestAuthenticate_RejectsWrongSecret proves tokens signed under a
// different secret (e.g. an attacker guessing a "default") are rejected.
func TestAuthenticate_RejectsWrongSecret(t *testing.T) {
	forger := New()
	fk := newTestKernel(t, map[string]any{"secret": "attacker-controlled-secret-000000"})
	if err := forger.Init(context.Background(), fk); err != nil {
		t.Fatalf("Init: %v", err)
	}
	forgedTok, err := forger.Issue("admin", []string{"admin"}, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	real := New()
	rk := newTestKernel(t, map[string]any{"secret": "0123456789abcdef0123456789abcdef"})
	if err := real.Init(context.Background(), rk); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := real.Authenticate(context.Background(), forgedTok); err == nil {
		t.Fatal("expected token forged under a different secret to be rejected")
	}
}

// TestIssueToken_RoundTripsThroughAuthenticate proves the api.TokenIssuer
// bridge (used by web's OIDC/LDAP login handlers to mint a usable Bearer
// token for an identity established via a non-JWT Authenticator) actually
// produces a token this same plugin's own Authenticate accepts, with the
// right Subject/Roles recovered.
func TestIssueToken_RoundTripsThroughAuthenticate(t *testing.T) {
	p := New()
	k := newTestKernel(t, map[string]any{"secret": "0123456789abcdef0123456789abcdef"})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	var issuer api.TokenIssuer = p // compile-time proof Plugin satisfies api.TokenIssuer
	tok, err := issuer.IssueToken(context.Background(), "bob", []string{"editor"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	principal, err := p.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "bob" {
		t.Fatalf("Subject = %q, want %q", principal.Subject, "bob")
	}
	if len(principal.Roles) != 1 || principal.Roles[0] != "editor" {
		t.Fatalf("Roles = %v, want [editor]", principal.Roles)
	}
}

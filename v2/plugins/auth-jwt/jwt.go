// Package authjwt implements the auth-jwt plugin: a JWT api.AuthProvider
// backed by github.com/golang-jwt/jwt/v5 (the same real library v1's
// pkg/web already used — not hand-rolled).
//
// SECURITY: v1's own pentest suite found a CRITICAL vulnerability where a
// default/hardcoded JWT secret allowed admin token forgery. This plugin
// closes that hole structurally: Init returns a hard error if no signing
// secret is configured, with no fallback default, ever. The only opt-out
// is an explicit `insecure_dev_mode: true` config flag, and even then a
// secret must still be supplied — insecure_dev_mode only relaxes the
// minimum-length check, it never invents a secret.
package authjwt

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/oarkflow/velocity/v2/api"
)

const (
	// PluginName is this plugin's boot-order Name().
	PluginName = "auth-jwt"
	// ServiceName is the registry name this plugin Provides its
	// api.AuthProvider under.
	ServiceName = "auth.jwt"

	minSecretLen = 32 // bytes, only enforced when insecure_dev_mode is false
)

// Plugin implements api.Plugin and api.AuthProvider.
type Plugin struct {
	mu      sync.RWMutex
	secret  []byte
	issuer  string
	log     api.Logger
	events  api.EventBus
	started bool
}

// New constructs an uninitialized auth-jwt plugin. All configuration is
// read from the manifest at Init time.
func New() *Plugin { return &Plugin{} }

var (
	_ api.Plugin       = (*Plugin)(nil)
	_ api.AuthProvider = (*Plugin)(nil)
	_ api.TokenIssuer  = (*Plugin)(nil)
)

func (p *Plugin) Name() string           { return PluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

// Init reads config and REFUSES TO START without an explicit secret. This
// is the fix for v1's critical default-JWT-secret finding: there is no
// code path in this plugin that picks a secret on the caller's behalf.
func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	cfg := k.Config().Scoped(PluginName)
	secret := cfg.String("secret", "")
	devMode := cfg.Bool("insecure_dev_mode", false)

	if secret == "" {
		return fmt.Errorf("auth-jwt: refusing to start: no signing secret configured " +
			"(set plugins.auth-jwt.config.secret in the manifest — there is no default, by design, " +
			"per the critical admin-token-forgery finding this plugin closes)")
	}
	if !devMode && len(secret) < minSecretLen {
		return fmt.Errorf("auth-jwt: refusing to start: secret is only %d bytes, minimum %d "+
			"(set insecure_dev_mode: true to relax this for local development only)", len(secret), minSecretLen)
	}

	p.secret = []byte(secret)
	p.issuer = cfg.String("issuer", "")
	p.log = k.Logger()
	p.events = k.Events()

	if err := k.Registry().Provide(ServiceName, p); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	p.started = true
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	p.started = false
	return nil
}

func (p *Plugin) Health() api.Health {
	if p.started {
		return api.Health{Status: "ok"}
	}
	return api.Health{Status: "down"}
}

// Claims is the token payload this plugin issues and validates.
type Claims struct {
	jwt.RegisteredClaims
	Roles []string       `json:"roles,omitempty"`
	Extra map[string]any `json:"extra,omitempty"`
}

// Issue mints a signed token for the given subject/roles, valid for ttl.
// Exposed as a concrete-type extension (not part of api.AuthProvider)
// since minting is an administrative action, not an authentication check.
func (p *Plugin) Issue(subject string, roles []string, ttl time.Duration) (string, error) {
	p.mu.RLock()
	secret := p.secret
	issuer := p.issuer
	p.mu.RUnlock()

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Roles: roles,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

// IssueToken implements api.TokenIssuer, so other plugins (notably web's
// OIDC/LDAP login bridge) can mint a session token for an identity they
// established some other way, via a plain registry lookup + type
// assertion — without importing this package directly. It's a thin
// context-accepting wrapper over Issue; the two are otherwise identical.
func (p *Plugin) IssueToken(ctx context.Context, subject string, roles []string, ttl time.Duration) (string, error) {
	return p.Issue(subject, roles, ttl)
}

// Name identifies this Authenticator/Authorizer (satisfies api.Authenticator's
// Name() alongside Plugin.Name() — both return PluginName, so one method
// serves both embedded interfaces).
func (p *Plugin) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	raw, ok := credential.(string)
	if !ok {
		return api.Principal{}, fmt.Errorf("auth-jwt: credential must be a raw JWT string, got %T", credential)
	}

	p.mu.RLock()
	secret := p.secret
	p.mu.RUnlock()

	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth-jwt: unexpected signing method %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil || !tok.Valid {
		p.deny(ctx, "", err)
		return api.Principal{}, fmt.Errorf("auth-jwt: invalid token: %w", err)
	}

	principal := api.Principal{
		Subject: claims.Subject,
		Roles:   claims.Roles,
		Claims:  claims.Extra,
	}
	if p.events != nil {
		p.events.Publish(ctx, api.Event{Topic: api.TopicAuthLogin, Source: PluginName, Payload: principal.Subject})
	}
	return principal, nil
}

func (p *Plugin) deny(ctx context.Context, subject string, reason error) {
	if p.events == nil {
		return
	}
	p.events.Publish(ctx, api.Event{
		Topic:  api.TopicAuthDenied,
		Source: PluginName,
		Payload: map[string]any{
			"subject": subject,
			"reason":  fmt.Sprint(reason),
		},
	})
}

// Authorize implements a minimal placeholder RBAC: role "admin" can do
// anything, everyone else is denied. Anything beyond this coarse gate
// belongs to the compliance plugin's PolicyEngine, which evaluates
// classification-aware rules — this method exists so auth-jwt satisfies
// api.AuthProvider standalone, not as the system's real authorization
// decision point.
func (p *Plugin) Authorize(ctx context.Context, principal api.Principal, action, resource string) (bool, error) {
	for _, r := range principal.Roles {
		if r == "admin" {
			return true, nil
		}
	}
	return false, nil
}

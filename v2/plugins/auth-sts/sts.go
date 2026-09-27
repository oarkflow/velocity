// Package authsts implements the auth-sts plugin: temporary security
// credentials / assume-role flows (direct, web-identity/OIDC, LDAP),
// session token generation/validation/revocation with expiry cleanup,
// ported from v1's sts.go.
//
// Unlike v1 (which persisted sessions via *DB), this plugin keeps
// sessions in an in-memory, mutex-guarded map with a background cleanup
// sweep. This is a deliberate scope simplification for the initial v2
// rework — wiring STS sessions through the "kv" service (so they survive
// a restart) is a natural follow-up once plugins/kv exists, and would
// only require swapping the storage in loadSession/saveSession/sweep for
// a Registry.Lookup("kv") call; the public API here would not change.
package authsts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	authldap "github.com/oarkflow/velocity/v2/plugins/auth-ldap"
	authoidc "github.com/oarkflow/velocity/v2/plugins/auth-oidc"
)

const (
	PluginName  = "auth-sts"
	ServiceName = "auth.sts"
)

// Credentials are temporary security credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// Session is an active STS session.
type Session struct {
	SessionToken    string
	AccessKeyID     string
	SecretAccessKey string
	UserID          string
	RoleARN         string
	SourceIdentity  string
	PolicyARNs      []string
	Expiration      time.Time
	CreatedAt       time.Time
	Revoked         bool
}

// AssumeRoleRequest describes a role to assume and, optionally, a
// federated credential (OIDC ID token or LDAP username/password) to
// establish the caller's identity before issuing temporary credentials.
// Exactly one federation method should be set, or none for a direct
// assume-role where UserID is already known/trusted by the caller.
type AssumeRoleRequest struct {
	RoleARN         string
	RoleSessionName string
	DurationSeconds int
	PolicyARNs      []string

	UserID string // set for a direct assume-role

	OIDCIDToken string // set for AssumeRoleWithWebIdentity
	LDAPUser    string // set for AssumeRoleWithLDAP
	LDAPPass    string
}

// AssumeRoleResult is the output of AssumeRole.
type AssumeRoleResult struct {
	Credentials   Credentials
	AssumedRoleID string
}

// Plugin implements api.Plugin and api.AuthProvider. AssumeRole is an
// additional exported method, not part of api.AuthProvider — assuming a
// role is an administrative action, not "authenticate a credential" —
// callers that need it should type-assert to *Plugin.
type Plugin struct {
	mu   sync.RWMutex
	sess map[string]*Session

	oidcDep string
	ldapDep string
	// oidc/ldap are stored as the generic api.Authenticator interface,
	// but Init below deliberately imports plugins/auth-oidc and
	// plugins/auth-ldap directly (a documented, justified exception to
	// this codebase's usual "depend only on v2/api" convention) because
	// federating a web-identity/LDAP assume-role genuinely requires
	// constructing THAT provider's own concrete Credential type — there is
	// no generic credential shape in v2/api that would let this be done
	// through the registry alone without one. This is a deliberate,
	// narrow coupling specific to STS federation, not a pattern to copy
	// elsewhere in this codebase.
	oidc api.Authenticator
	ldap api.Authenticator

	// roleMappings maps an OIDC claim value or LDAP group name to a role
	// string attached to the issued session — see loadRoleMappings.
	roleMappings map[string]string

	events  api.EventBus
	log     api.Logger
	stopCh  chan struct{}
	started bool
}

// NewWithDeps constructs an auth-sts plugin that, if the named plugins are
// enabled, uses them for AssumeRoleWithWebIdentity / AssumeRoleWithLDAP.
// Pass "" for either to disable that federation method. Defaults to no
// dependency (nil, nil), matching New().
func NewWithDeps(oidcDep, ldapDep string) *Plugin {
	return &Plugin{sess: map[string]*Session{}, stopCh: make(chan struct{}), oidcDep: oidcDep, ldapDep: ldapDep}
}

func New() *Plugin { return NewWithDeps("", "") }

var (
	_ api.Plugin       = (*Plugin)(nil)
	_ api.AuthProvider = (*Plugin)(nil)
)

func (p *Plugin) Name() string    { return PluginName }
func (p *Plugin) Version() string { return "0.1.0" }
func (p *Plugin) Dependencies() []string {
	var deps []string
	if p.oidcDep != "" {
		deps = append(deps, p.oidcDep)
	}
	if p.ldapDep != "" {
		deps = append(deps, p.ldapDep)
	}
	return deps
}

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.events = k.Events()
	p.log = k.Logger()

	if p.oidcDep != "" {
		svc := k.Registry().MustLookup(p.oidcDep)
		auth, ok := svc.(api.Authenticator)
		if !ok {
			return fmt.Errorf("sts: service %q does not implement api.Authenticator", p.oidcDep)
		}
		p.oidc = auth
	}
	if p.ldapDep != "" {
		svc := k.Registry().MustLookup(p.ldapDep)
		auth, ok := svc.(api.Authenticator)
		if !ok {
			return fmt.Errorf("sts: service %q does not implement api.Authenticator", p.ldapDep)
		}
		p.ldap = auth
	}

	p.roleMappings = loadRoleMappings(k.Config().Scoped(PluginName).Raw())

	return k.Registry().Provide(ServiceName, p)
}

func (p *Plugin) Start(ctx context.Context) error {
	go p.cleanupLoop()
	p.started = true
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	close(p.stopCh)
	p.started = false
	return nil
}

func (p *Plugin) Health() api.Health {
	if p.started {
		return api.Health{Status: "ok"}
	}
	return api.Health{Status: "down"}
}

func (p *Plugin) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.cleanupExpired()
		case <-p.stopCh:
			return
		}
	}
}

func (p *Plugin) cleanupExpired() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	removed := 0
	for tok, s := range p.sess {
		if now.After(s.Expiration) {
			delete(p.sess, tok)
			removed++
		}
	}
	return removed
}

// loadRoleMappings reads a "role_mappings" config entry shaped as
// {"role_mappings": {"claim-or-group-value": "arn:policy:..."}} and
// returns it as a plain map, or nil if absent/malformed (a missing
// mapping config is not an error — federation still works, it just won't
// auto-attach a PolicyARN unless the caller supplied one directly).
func loadRoleMappings(cfg map[string]any) map[string]string {
	raw, ok := cfg["role_mappings"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func clampDuration(seconds int) time.Duration {
	d := time.Duration(seconds) * time.Second
	if d == 0 {
		d = time.Hour
	}
	if d < 15*time.Minute {
		d = 15 * time.Minute
	}
	if d > 12*time.Hour {
		d = 12 * time.Hour
	}
	return d
}

func generateCredentials(duration time.Duration) (Credentials, error) {
	accessKey, err := generateSecureToken(20)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts: failed to generate access key: %w", err)
	}
	secretKey, err := generateSecureToken(40)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts: failed to generate secret key: %w", err)
	}
	sessionToken, err := generateSecureToken(64)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts: failed to generate session token: %w", err)
	}
	return Credentials{
		AccessKeyID:     "AKIA" + strings.ToUpper(accessKey[:16]),
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
		Expiration:      time.Now().Add(duration),
	}, nil
}

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])[:length], nil
}

// AssumeRole issues temporary credentials. If req.OIDCIDToken or
// req.LDAPUser/LDAPPass are set, the corresponding federation method is
// used to establish UserID; otherwise req.UserID must already be set by
// the caller (a "direct" assume-role, mirroring v1's AssumeRole).
func (p *Plugin) AssumeRole(ctx context.Context, req AssumeRoleRequest) (*AssumeRoleResult, error) {
	if req.RoleARN == "" {
		return nil, fmt.Errorf("sts: RoleARN is required")
	}
	if req.RoleSessionName == "" {
		return nil, fmt.Errorf("sts: RoleSessionName is required")
	}

	userID := req.UserID
	var federatedRoles []string
	switch {
	case req.OIDCIDToken != "":
		if p.oidc == nil {
			return nil, fmt.Errorf("sts: AssumeRoleWithWebIdentity requires auth-oidc to be configured (NewWithDeps oidcDep) and enabled in the manifest, which it is not in this deployment")
		}
		principal, err := p.oidc.Authenticate(ctx, authoidc.Credential{IDToken: req.OIDCIDToken})
		if err != nil {
			return nil, fmt.Errorf("sts: web identity token validation failed: %w", err)
		}
		userID = principal.Subject
		federatedRoles = principal.Roles
	case req.LDAPUser != "":
		if p.ldap == nil {
			return nil, fmt.Errorf("sts: AssumeRoleWithLDAP requires auth-ldap to be configured (NewWithDeps ldapDep) and enabled in the manifest, which it is not in this deployment")
		}
		principal, err := p.ldap.Authenticate(ctx, authldap.Credential{Username: req.LDAPUser, Password: req.LDAPPass})
		if err != nil {
			return nil, fmt.Errorf("sts: LDAP authentication failed: %w", err)
		}
		userID = principal.Subject
		federatedRoles = principal.Roles
	}
	if userID == "" {
		return nil, fmt.Errorf("sts: no UserID established (set UserID directly, or a federation credential)")
	}

	// Config-driven claim/group -> role mapping: if the federated
	// principal carries a role this plugin's "role_mappings" config
	// recognizes, and the caller didn't already specify PolicyARNs,
	// attach the mapped policy ARN(s). This is intentionally simple
	// (exact-match lookup, first match wins) rather than a full policy
	// language — see loadRoleMappings.
	if len(req.PolicyARNs) == 0 && len(p.roleMappings) > 0 {
		for _, r := range federatedRoles {
			if arn, ok := p.roleMappings[r]; ok {
				req.PolicyARNs = append(req.PolicyARNs, arn)
			}
		}
	}

	duration := clampDuration(req.DurationSeconds)
	creds, err := generateCredentials(duration)
	if err != nil {
		return nil, err
	}

	session := &Session{
		SessionToken:    creds.SessionToken,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		UserID:          userID,
		RoleARN:         req.RoleARN,
		SourceIdentity:  req.RoleSessionName,
		PolicyARNs:      req.PolicyARNs,
		Expiration:      creds.Expiration,
		CreatedAt:       time.Now(),
	}
	p.mu.Lock()
	p.sess[session.SessionToken] = session
	p.mu.Unlock()

	return &AssumeRoleResult{
		Credentials:   creds,
		AssumedRoleID: fmt.Sprintf("%s:%s", req.RoleARN, req.RoleSessionName),
	}, nil
}

func (p *Plugin) validateSessionToken(token string) (*Session, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.sess[token]
	if !ok {
		return nil, fmt.Errorf("sts: invalid session token")
	}
	if s.Revoked {
		return nil, fmt.Errorf("sts: session has been revoked")
	}
	if time.Now().After(s.Expiration) {
		return nil, fmt.Errorf("sts: session has expired")
	}
	return s, nil
}

// RevokeSession marks a session as revoked.
func (p *Plugin) RevokeSession(token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sess[token]
	if !ok {
		return fmt.Errorf("sts: session not found")
	}
	s.Revoked = true
	return nil
}

// Authenticate validates an STS session token (credential must be the raw
// session token string) and returns the Principal it was issued for.
func (p *Plugin) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	token, ok := credential.(string)
	if !ok {
		return api.Principal{}, fmt.Errorf("auth-sts: credential must be a session token string, got %T", credential)
	}
	s, err := p.validateSessionToken(token)
	if err != nil {
		p.deny(ctx, "", err)
		return api.Principal{}, err
	}
	principal := api.Principal{
		Subject: s.UserID,
		Claims:  map[string]any{"role_arn": s.RoleARN, "source_identity": s.SourceIdentity},
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
		Topic:   api.TopicAuthDenied,
		Source:  PluginName,
		Payload: map[string]any{"subject": subject, "reason": fmt.Sprint(reason)},
	})
}

// Authorize is a minimal placeholder: assumed-role sessions carrying
// PolicyARNs are out of scope for this coarse check — the compliance
// plugin's PolicyEngine is the real authorization decision point.
func (p *Plugin) Authorize(ctx context.Context, principal api.Principal, action, resource string) (bool, error) {
	return false, nil
}

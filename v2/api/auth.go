package api

import (
	"context"
	"time"
)

// Principal is the authenticated identity produced by an Authenticator and
// consumed by an Authorizer / PolicyEngine.
type Principal struct {
	Subject string
	Roles   []string
	Claims  map[string]any
}

// Authenticator validates a credential and produces a Principal. Multiple
// Authenticators can be registered simultaneously under distinct names
// (e.g. "auth-jwt", "auth-ldap", "auth-oidc", "auth-sts") and the web
// plugin picks the appropriate one per request.
//
// Unlike v1, an auth-jwt implementation MUST refuse to Init/Start without
// an explicit signing secret/key supplied via config — there is no
// built-in default secret. This closes the critical admin-token-forgery
// finding from v1's own pentest suite.
type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context, credential any) (Principal, error)
}

// Authorizer makes an allow/deny decision for an already-authenticated
// Principal. plugins/compliance's PolicyEngine is one Authorizer; simple
// role-based authorizers can be simpler standalone plugins.
type Authorizer interface {
	Authorize(ctx context.Context, p Principal, action, resource string) (bool, error)
}

// AuthProvider is the combined surface a single auth plugin registers
// under its own name (e.g. "auth-jwt"). Plugins needing only one half can
// still implement both and no-op the other, but most auth plugins are
// naturally both an Authenticator and Authorizer.
type AuthProvider interface {
	Authenticator
	Authorizer
}

// MFAProvider is a second-factor verifier, kept as its own interface
// (rather than folded into Authenticator) because MFA is an additional
// check layered on top of a primary credential, not an alternative way to
// establish identity — a caller authenticates via an Authenticator first,
// then separately calls ValidateCode against the resulting subject before
// treating the session as fully authenticated.
//
// Ported from v1's pkg/auth/mfa.go (RFC 4226 HOTP / RFC 6238 TOTP).
// Service name: "mfa" -> api.MFAProvider.
type MFAProvider interface {
	// GenerateSecret creates and persists a new TOTP secret for subject,
	// returning it base32-encoded (suitable for a QR-code provisioning
	// URI). Calling this again for the same subject replaces the secret.
	GenerateSecret(ctx context.Context, subject string) (secretBase32 string, err error)

	// ValidateCode checks a 6-digit TOTP code for subject against the
	// current time step, tolerating a small clock-skew window. Returns
	// (false, nil) for a wrong code, and a non-nil error only for
	// operational failures (e.g. subject has no secret yet).
	ValidateCode(ctx context.Context, subject, code string) (bool, error)
}

// TokenIssuer is an optional capability an Authenticator MAY also
// implement (auth-jwt does) to mint a new session token for an identity
// already established some other way — e.g. a caller who authenticated
// via auth-oidc or auth-ldap and now needs a Bearer token usable against
// this process's own auth-jwt-protected routes. Kept as its own interface
// (rather than folded into Authenticator/AuthProvider) since minting a
// token is an administrative action taken on a Principal already
// established by some Authenticate call, not itself a way of
// establishing one.
//
// A caller doing this bridge should: Authenticate via whichever
// Authenticator validated the original credential, then — if a
// TokenIssuer is also registered (commonly the SAME "auth.jwt" service,
// type-asserted) — call IssueToken with the resulting Principal's
// Subject/Roles to obtain a token usable against auth-jwt-protected
// routes going forward. If no TokenIssuer is registered, the caller
// should fall back to returning the bare Principal rather than failing
// outright — token issuance is a convenience bridge, not a hard
// requirement of authentication succeeding.
type TokenIssuer interface {
	IssueToken(ctx context.Context, subject string, roles []string, ttl time.Duration) (token string, err error)
}

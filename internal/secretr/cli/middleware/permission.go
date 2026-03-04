// Package middleware provides CLI middleware for permission gating.
package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// ContextKey type for context keys
type ContextKey string

const (
	// SessionContextKey is the context key for the current session
	SessionContextKey ContextKey = "session"
	// IdentityContextKey is the context key for the current identity
	IdentityContextKey ContextKey = "identity"
	// ScopesContextKey is the context key for available scopes
	ScopesContextKey ContextKey = "scopes"
)

// PermissionGate provides scope-based command gating
type PermissionGate struct {
	sessionProvider SessionProvider
	auditLogger     AuditLogger
}

// SessionProvider provides the current session
type SessionProvider interface {
	GetCurrentSession(ctx context.Context) (*types.Session, error)
	GetIdentity(ctx context.Context, id types.ID) (*types.Identity, error)
}

// AuditLogger logs permission checks
type AuditLogger interface {
	LogPermissionCheck(ctx context.Context, event PermissionCheckEvent)
}

// PermissionCheckEvent represents a permission check
type PermissionCheckEvent struct {
	SessionID      types.ID
	IdentityID     types.ID
	RequiredScopes []types.Scope
	GrantedScopes  []types.Scope
	Allowed        bool
	Command        string
	Resource       string
}

// NewPermissionGate creates a new permission gate
func NewPermissionGate(sessionProvider SessionProvider, auditLogger AuditLogger) *PermissionGate {
	return &PermissionGate{
		sessionProvider: sessionProvider,
		auditLogger:     auditLogger,
	}
}

// RequireScopes returns a middleware that requires specific scopes
func (pg *PermissionGate) RequireScopes(scopes ...types.Scope) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		// If no session provider, skip permission check (for commands that don't need auth)
		if pg.sessionProvider == nil {
			return ctx, nil
		}

		// Get current session
		session, err := pg.sessionProvider.GetCurrentSession(ctx)
		if err != nil {
			return ctx, &types.Error{
				Code:    types.ErrCodeUnauthorized,
				Message: "No active session. Please login first.",
			}
		}

		// Check if session is active
		if !session.IsActive() {
			return ctx, &types.Error{
				Code:    types.ErrCodeExpired,
				Message: "Session has expired. Please login again.",
			}
		}

		// Check if session has required scopes
		missingScopes := make([]types.Scope, 0)
		for _, scope := range scopes {
			if !session.Scopes.Has(scope) {
				missingScopes = append(missingScopes, scope)
			}
		}

		// Log the permission check
		if pg.auditLogger != nil {
			pg.auditLogger.LogPermissionCheck(ctx, PermissionCheckEvent{
				SessionID:      session.ID,
				IdentityID:     session.IdentityID,
				RequiredScopes: scopes,
				GrantedScopes:  session.Scopes.Scopes(),
				Allowed:        len(missingScopes) == 0,
				Command:        cmd.FullName(),
			})
		}

		if len(missingScopes) > 0 {
			scopeStrs := make([]string, len(missingScopes))
			for i, s := range missingScopes {
				scopeStrs[i] = string(s)
			}
			return ctx, &types.Error{
				Code:    types.ErrCodeScopeRequired,
				Message: fmt.Sprintf("Missing required scopes: %s", strings.Join(scopeStrs, ", ")),
				Details: types.Metadata{
					"required_scopes": scopeStrs,
				},
			}
		}

		// Add session and scopes to context
		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, ScopesContextKey, session.Scopes)

		return ctx, nil
	}
}

// RequireAnyScope returns a middleware that requires any of the specified scopes
func (pg *PermissionGate) RequireAnyScope(scopes ...types.Scope) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		session, err := pg.sessionProvider.GetCurrentSession(ctx)
		if err != nil {
			return ctx, &types.Error{
				Code:    types.ErrCodeUnauthorized,
				Message: "No active session. Please login first.",
			}
		}

		if !session.IsActive() {
			return ctx, &types.Error{
				Code:    types.ErrCodeExpired,
				Message: "Session has expired. Please login again.",
			}
		}

		if !session.Scopes.HasAny(scopes...) {
			scopeStrs := make([]string, len(scopes))
			for i, s := range scopes {
				scopeStrs[i] = string(s)
			}
			return ctx, &types.Error{
				Code:    types.ErrCodeScopeRequired,
				Message: fmt.Sprintf("Requires at least one of: %s", strings.Join(scopeStrs, ", ")),
			}
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, ScopesContextKey, session.Scopes)

		return ctx, nil
	}
}

// RequireAuthenticated returns a middleware that only requires authentication
func (pg *PermissionGate) RequireAuthenticated() cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if pg.sessionProvider == nil {
			return ctx, nil
		}

		session, err := pg.sessionProvider.GetCurrentSession(ctx)
		if err != nil {
			return ctx, &types.Error{
				Code:    types.ErrCodeUnauthorized,
				Message: "No active session. Please login first.",
			}
		}

		if !session.IsActive() {
			return ctx, &types.Error{
				Code:    types.ErrCodeExpired,
				Message: "Session has expired. Please login again.",
			}
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, ScopesContextKey, session.Scopes)

		return ctx, nil
	}
}

// RequireMFA returns a middleware that requires MFA verification
func (pg *PermissionGate) RequireMFA() cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if pg.sessionProvider == nil {
			return ctx, nil
		}

		session, err := pg.sessionProvider.GetCurrentSession(ctx)
		if err != nil {
			return ctx, &types.Error{
				Code:    types.ErrCodeUnauthorized,
				Message: "No active session. Please login first.",
			}
		}

		if !session.MFAVerified {
			return ctx, &types.Error{
				Code:    types.ErrCodeForbidden,
				Message: "Multi-factor authentication required for this operation.",
			}
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		return ctx, nil
	}
}

// RequireAdmin returns a middleware that requires admin scope
func (pg *PermissionGate) RequireAdmin() cli.BeforeFunc {
	return pg.RequireScopes(types.ScopeAdminAll)
}

// RequireIncidentFreeOrAdmin returns a middleware that checks incident status
func (pg *PermissionGate) RequireIncidentFreeOrAdmin(orgChecker OrgChecker) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if pg.sessionProvider == nil {
			return ctx, nil
		}

		session, err := pg.sessionProvider.GetCurrentSession(ctx)
		if err != nil {
			return ctx, &types.Error{
				Code:    types.ErrCodeUnauthorized,
				Message: "No active session.",
			}
		}

		// Admin can bypass incident freeze
		if session.Scopes.Has(types.ScopeAdminAll) {
			ctx = context.WithValue(ctx, SessionContextKey, session)
			return ctx, nil
		}

		// Check if organization is in incident freeze mode
		frozen, err := orgChecker.IsIncidentFrozen(ctx)
		if err != nil {
			return ctx, err
		}

		if frozen {
			return ctx, &types.Error{
				Code:    types.ErrCodeIncidentFrozen,
				Message: "Organization is in incident freeze mode. Only admin operations are allowed.",
			}
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		return ctx, nil
	}
}

// OrgChecker checks organization status
type OrgChecker interface {
	IsIncidentFrozen(ctx context.Context) (bool, error)
}

// Chain chains multiple before functions
func Chain(funcs ...cli.BeforeFunc) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		var err error
		for _, fn := range funcs {
			ctx, err = fn(ctx, cmd)
			if err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	}
}

// GetSession retrieves the session from context
func GetSession(ctx context.Context) *types.Session {
	session, _ := ctx.Value(SessionContextKey).(*types.Session)
	return session
}

// GetScopes retrieves the scopes from context
func GetScopes(ctx context.Context) types.ScopeSet {
	scopes, _ := ctx.Value(ScopesContextKey).(types.ScopeSet)
	return scopes
}

// HasScope checks if the context has a specific scope
func HasScope(ctx context.Context, scope types.Scope) bool {
	scopes := GetScopes(ctx)
	return scopes != nil && scopes.Has(scope)
}

// CommandPermissions maps commands to required scopes
var CommandPermissions = map[string][]types.Scope{
	// Auth commands
	"auth login":        {},
	"auth logout":       {types.ScopeAuthLogout},
	"auth status":       {types.ScopeAuthLogin},
	"auth rotate-token": {types.ScopeAuthRotate},

	// Identity commands
	"identity create":  {types.ScopeIdentityCreate},
	"identity list":    {types.ScopeIdentityRead},
	"identity get":     {types.ScopeIdentityRead},
	"identity update":  {types.ScopeIdentityUpdate},
	"identity delete":  {types.ScopeIdentityDelete},
	"identity revoke":  {types.ScopeIdentityDelete},
	"identity recover": {types.ScopeIdentityRecover},

	// Device commands
	"device enroll": {types.ScopeDeviceEnroll},
	"device list":   {types.ScopeDeviceRead},
	"device get":    {types.ScopeDeviceRead},
	"device revoke": {types.ScopeDeviceRevoke},
	"device trust":  {types.ScopeDeviceTrust},

	// Session commands
	"session list":   {types.ScopeSessionRead},
	"session revoke": {types.ScopeSessionRevoke},

	// Key commands
	"key generate": {types.ScopeKeyGenerate},
	"key list":     {types.ScopeKeyRead},
	"key get":      {types.ScopeKeyRead},
	"key rotate":   {types.ScopeKeyRotate},
	"key destroy":  {types.ScopeKeyDestroy},
	"key export":   {types.ScopeKeyExport},
	"key import":   {types.ScopeKeyImport},

	// Secret commands
	"secret create":  {types.ScopeSecretCreate},
	"secret list":    {types.ScopeSecretList},
	"secret get":     {types.ScopeSecretRead},
	"secret update":  {types.ScopeSecretUpdate},
	"secret delete":  {types.ScopeSecretDelete},
	"secret history": {types.ScopeSecretHistory},
	"secret rotate":  {types.ScopeSecretRotate},
	"secret share":   {types.ScopeSecretShare},
	"secret export":  {types.ScopeSecretExport},

	// File commands
	"file upload":   {types.ScopeFileUpload},
	"file list":     {types.ScopeFileList},
	"file download": {types.ScopeFileDownload},
	"file delete":   {types.ScopeFileDelete},
	"file seal":     {types.ScopeFileSeal},
	"file unseal":   {types.ScopeFileUnseal},
	"file shred":    {types.ScopeFileShred},
	"file share":    {types.ScopeFileShare},

	// Access commands
	"access grant":    {types.ScopeAccessGrant},
	"access revoke":   {types.ScopeAccessRevoke},
	"access list":     {types.ScopeAccessRead},
	"access delegate": {types.ScopeAccessDelegate},
	"access approve":  {types.ScopeAccessApprove},

	// Role commands
	"role create": {types.ScopeRoleCreate},
	"role list":   {types.ScopeRoleRead},
	"role get":    {types.ScopeRoleRead},
	"role update": {types.ScopeRoleUpdate},
	"role delete": {types.ScopeRoleDelete},
	"role assign": {types.ScopeRoleAssign},

	// Policy commands
	"policy create":   {types.ScopePolicyCreate},
	"policy list":     {types.ScopePolicyRead},
	"policy get":      {types.ScopePolicyRead},
	"policy update":   {types.ScopePolicyUpdate},
	"policy delete":   {types.ScopePolicyDelete},
	"policy bind":     {types.ScopePolicyBind},
	"policy simulate": {types.ScopePolicySimulate},
	"policy freeze":   {types.ScopePolicyFreeze, types.ScopeAdminAll},

	// Audit commands
	"audit query":  {types.ScopeAuditQuery},
	"audit export": {types.ScopeAuditExport},
	"audit verify": {types.ScopeAuditVerify},
	"audit redact": {types.ScopeAuditRedact, types.ScopeAdminAll},

	// Share commands
	"share create": {types.ScopeShareCreate},
	"share list":   {types.ScopeShareRead},
	"share revoke": {types.ScopeShareRevoke},
	"share accept": {types.ScopeShareAccept},
	"share export": {types.ScopeShareExport},

	// Backup commands
	"backup create":   {types.ScopeBackupCreate},
	"backup list":     {types.ScopeBackupCreate},
	"backup verify":   {types.ScopeBackupVerify},
	"backup restore":  {types.ScopeBackupRestore},
	"backup schedule": {types.ScopeBackupSchedule},

	// Organization commands
	"org create":       {types.ScopeOrgCreate},
	"org list":         {types.ScopeOrgRead},
	"org get":          {types.ScopeOrgRead},
	"org update":       {types.ScopeOrgUpdate},
	"org invite":       {types.ScopeOrgInvite},
	"org revoke":       {types.ScopeOrgRevoke},
	"org teams":        {types.ScopeOrgTeams},
	"org environments": {types.ScopeOrgEnv},
	"org compliance":   {types.ScopeOrgCompliance},
	"org legal-hold":   {types.ScopeOrgLegalHold, types.ScopeAdminAll},

	// Incident commands
	"incident declare":  {types.ScopeIncidentDeclare},
	"incident freeze":   {types.ScopeIncidentFreeze},
	"incident rotate":   {types.ScopeIncidentRotate},
	"incident export":   {types.ScopeIncidentExport},
	"incident monitor":  {types.ScopeIncidentMonitor},
	"incident timeline": {types.ScopeIncidentTimeline},

	// Envelope commands
	"envelope create": {types.ScopeEnvelopeCreate},
	"envelope open":   {types.ScopeEnvelopeOpen},
	"envelope verify": {types.ScopeEnvelopeVerify},

	// Admin commands
	"admin users":    {types.ScopeAdminUsers},
	"admin system":   {types.ScopeAdminSystem},
	"admin security": {types.ScopeAdminSecurity},
}

// GetRequiredScopes returns the required scopes for a command
func GetRequiredScopes(command string) []types.Scope {
	scopes, ok := CommandPermissions[command]
	if !ok {
		return nil
	}
	return scopes
}

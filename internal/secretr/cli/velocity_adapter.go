package cli

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Global adapter for setting client when it's initialized
var globalAdapter *VelocityAdapter

// SetGlobalAdapter sets the global adapter instance
func SetGlobalAdapter(adapter *VelocityAdapter) {
	globalAdapter = adapter
}

// GetGlobalAdapter returns the globally configured Velocity adapter instance.
func GetGlobalAdapter() *VelocityAdapter {
	return globalAdapter
}

// VelocityAdapter adapts secretr client to work with velocity commands
type VelocityAdapter struct {
	client     *Client
	velocityDB *velocity.DB
}

// NewVelocityAdapter creates a new adapter
func NewVelocityAdapter(client *Client, velocityDB *velocity.DB) *VelocityAdapter {
	return &VelocityAdapter{
		client:     client,
		velocityDB: velocityDB,
	}
}

// GetClient returns the secretr client
func (a *VelocityAdapter) GetClient() *Client {
	return a.client
}

// SetClient updates the secretr client
func (a *VelocityAdapter) SetClient(client *Client) {
	a.client = client
}

// GetVelocityDB returns the velocity DB
func (a *VelocityAdapter) GetVelocityDB() *velocity.DB {
	return a.velocityDB
}

// PermissionChecker wraps secretr's permission system for velocity
type SecretsPermissionChecker struct {
	client *Client
}

// NewSecretsPermissionChecker creates a permission checker for secretr
func NewSecretsPermissionChecker(client *Client) *SecretsPermissionChecker {
	return &SecretsPermissionChecker{client: client}
}

// HasPermission checks if the current user has the required permission
func (c *SecretsPermissionChecker) HasPermission(user string, required velocitycli.Permission) bool {
	// If no client or no session, deny access except for public
	if c.client == nil || c.client.session == nil {
		return required == velocitycli.PermissionPublic
	}

	// Map velocity permissions to secretr scopes
	switch required {
	case velocitycli.PermissionPublic:
		return true
	case velocitycli.PermissionUser:
		// Any authenticated user has user permission
		return true
	case velocitycli.PermissionAdmin:
		// Check if user has admin scopes
		return c.hasAdminScopes()
	case velocitycli.PermissionOwner:
		// Check if user is owner/root
		return c.isOwner()
	default:
		return false
	}
}

// hasAdminScopes checks if the session has administrative scopes
func (c *SecretsPermissionChecker) hasAdminScopes() bool {
	if c.client == nil || c.client.session == nil {
		return false
	}

	// Check for admin-level scopes
	adminScopes := []types.Scope{
		types.ScopeIdentityCreate,
		types.ScopeIdentityDelete,
		types.ScopeOrgCreate,
		types.ScopePolicyCreate,
		types.ScopeIncidentDeclare,
	}

	for _, scope := range adminScopes {
		if c.hasScope(scope) {
			return true
		}
	}
	return false
}

// isOwner checks if the session belongs to an owner
func (c *SecretsPermissionChecker) isOwner() bool {
	if c.client == nil || c.client.session == nil {
		return false
	}

	// Owner has all scopes or is marked as admin in identity
	return c.hasScope("*") || c.hasAdminScopes()
}

// hasScope checks if session has a specific scope
func (c *SecretsPermissionChecker) hasScope(scope types.Scope) bool {
	if c.client == nil || c.client.session == nil {
		return false
	}

	return c.client.session.Scopes.Has(scope)
}

// SecretsContext wraps context with secretr session
type SecretsContext struct {
	context.Context
	session *types.Session
}

// GetSession returns the session from context
func GetSessionFromContext(ctx context.Context) *types.Session {
	if sctx, ok := ctx.(*SecretsContext); ok {
		return sctx.session
	}
	return nil
}

// NewSecretsContext creates a new context with session
func NewSecretsContext(ctx context.Context, session *types.Session) context.Context {
	return &SecretsContext{
		Context: ctx,
		session: session,
	}
}

// Value returns the value associated with this context for key
func (c *SecretsContext) Value(key interface{}) interface{} {
	if key == "session" {
		return c.session
	}
	return c.Context.Value(key)
}

// InitializeVelocityDB initializes a velocity DB instance for secretr
func InitializeVelocityDB(dataDir string, masterKey []byte) (*velocity.DB, error) {
	keySource := velocity.SystemFile
	if len(masterKey) > 0 {
		keySource = velocity.UserDefined
	}
	jwtSecret := resolveOrCreateJWTSecret(dataDir)

	config := velocity.Config{
		Path: dataDir + "/data",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: keySource,
		},
		MaxUploadSize: 100 * 1024 * 1024, // 100MB
		JWTSecret:     jwtSecret,
	}
	if len(masterKey) > 0 {
		config.MasterKey = masterKey
	}

	// Note: velocity uses Source field for key management
	// The actual key is provided when needed through MasterKey interface

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize velocity DB: %w", err)
	}

	return db, nil
}

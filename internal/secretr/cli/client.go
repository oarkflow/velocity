// Package cli provides the CLI client infrastructure.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/internal/secretr/core/access"
	"github.com/oarkflow/velocity/internal/secretr/core/alerts"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/automation"
	"github.com/oarkflow/velocity/internal/secretr/core/backup"
	"github.com/oarkflow/velocity/internal/secretr/core/cicd"
	"github.com/oarkflow/velocity/internal/secretr/core/compliance"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/incident"
	"github.com/oarkflow/velocity/internal/secretr/core/keys"
	"github.com/oarkflow/velocity/internal/secretr/core/monitoring"
	"github.com/oarkflow/velocity/internal/secretr/core/org"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/core/ssh"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Client provides access to all Secretr components
type Client struct {
	Store      *storage.Store
	Identity   *identity.Manager
	Keys       *keys.Manager
	Crypto     *crypto.Engine
	Secrets    *secrets.Vault
	Files      *files.Vault
	Access     *access.Manager
	Policy     *policy.Engine
	Audit      *audit.Engine
	Org        *org.Manager
	Incident   *incident.Manager
	Backup     *backup.Manager
	Share      *share.Manager
	SSH        *ssh.Manager
	CICD       *cicd.Manager
	Monitoring *monitoring.Engine
	Alerts     *alerts.Engine
	Compliance *compliance.Engine
	DLP        *compliance.DLPEngine
	Automation *automation.Manager

	// Session state
	session     *types.Session
	sessionPath string
}

// Config holds client configuration
type Config struct {
	DataDir     string
	SessionFile string
	MasterKey   []byte
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".secretr")

	return Config{
		DataDir:     dataDir,
		SessionFile: filepath.Join(dataDir, "session.json"),
	}
}

// NewClient creates a new Secretr client
func NewClient(cfg Config) (*Client, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Initialize store with encryption key
	keySource := velocity.SystemFile
	if len(cfg.MasterKey) > 0 {
		keySource = velocity.UserDefined
	}
	jwtSecret := resolveOrCreateJWTSecret(cfg.DataDir)
	storeConfig := storage.Config{
		Path:      filepath.Join(cfg.DataDir, "data"),
		KeySource: keySource,
		JWTSecret: jwtSecret,
	}
	if len(cfg.MasterKey) > 0 {
		storeConfig.EncryptionKey = cfg.MasterKey
	}
	store, err := storage.NewStore(storeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}
	fmt.Fprintf(os.Stderr, "secretr: vault path: %s\n", storeConfig.Path)

	// Initialize audit engine first (used by other managers)
	auditEngine := audit.NewEngine(audit.EngineConfig{
		Store: store,
	})
	if ok, err := auditEngine.VerifyIntegrity(context.Background()); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("security: failed to verify audit chain integrity: %w", err)
	} else if !ok {
		_ = store.Close()
		return nil, fmt.Errorf("security: audit chain integrity verification failed")
	}
	if ok, err := auditEngine.VerifyLedgerIntegrity(context.Background()); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("security: failed to verify ledger integrity: %w", err)
	} else if !ok {
		_ = store.Close()
		return nil, fmt.Errorf("security: audit ledger integrity verification failed")
	}

	// Initialize all managers
	client := &Client{
		Store:       store,
		Crypto:      crypto.NewEngine(""),
		sessionPath: cfg.SessionFile,
	}

	client.Identity = identity.NewManager(identity.ManagerConfig{
		Store: store,
	})

	keys, err := keys.NewManager(keys.ManagerConfig{
		Store:     store,
		MasterKey: cfg.MasterKey, // Use the provided master key directly
	})

	if err != nil {
		return nil, err
	}
	client.Keys = keys
	client.Secrets = secrets.NewVault(secrets.VaultConfig{
		Store:      store,
		KeyManager: client.Keys,
	})

	// Initialize Protection Manager
	protectionManager := files.NewProtectionManager(files.ProtectionManagerConfig{
		Store: store,
	})

	client.Files = files.NewVault(files.VaultConfig{
		Store:      store,
		KeyManager: client.Keys,
		Protection: protectionManager,
	})

	client.Access = access.NewManager(access.ManagerConfig{
		Store: store,
	})

	client.Policy = policy.NewEngine(policy.EngineConfig{
		Store: store,
	})

	client.Audit = auditEngine

	client.Org = org.NewManager(org.ManagerConfig{
		Store: store,
	})

	client.Incident = incident.NewManager(incident.ManagerConfig{
		Store:       store,
		AuditEngine: auditEngine,
	})

	client.Backup = backup.NewManager(backup.ManagerConfig{
		Store: store,
	})

	client.Share = share.NewManager(share.ManagerConfig{
		Store: store,
	})

	client.SSH = ssh.NewManager(ssh.ManagerConfig{
		Store:       store,
		AuditEngine: auditEngine,
	})

	client.CICD = cicd.NewManager(cicd.ManagerConfig{
		Store:       store,
		AuditEngine: auditEngine,
		SecretRetriever: func(ctx context.Context, secretID types.ID, env string) (string, error) {
			if v, found, err := LookupVelocitySecretValue(string(secretID)); err != nil {
				return "", err
			} else if found {
				return v, nil
			}
			mfa := false
			if sess := client.CurrentSession(); sess != nil {
				mfa = sess.MFAVerified
			}
			val, err := client.Secrets.Get(ctx, string(secretID), client.CurrentIdentityID(), mfa)
			if err != nil {
				return "", err
			}
			return string(val), nil
		},
	})

	client.Monitoring = monitoring.NewEngine(monitoring.EngineConfig{
		Store:       store,
		AuditEngine: auditEngine,
	})

	client.Alerts = alerts.NewEngine(alerts.EngineConfig{
		Store:      store,
		Monitoring: client.Monitoring,
	})

	client.Compliance = compliance.NewEngine(compliance.EngineConfig{
		Store:        store,
		AuditEngine:  auditEngine,
		PolicyEngine: client.Policy,
	})

	client.DLP = compliance.NewDLPEngine(compliance.DLPEngineConfig{
		Store: store,
	})

	client.Automation = automation.NewManager(automation.ManagerConfig{
		Store:  store,
		Crypto: client.Crypto,
	})

	client.registerDefaultAutomationHandlers()

	// Load session if exists
	client.loadSession()

	return client, nil
}

// Close closes the client
func (c *Client) Close() error {
	if c.Store != nil {
		return c.Store.Close()
	}
	return nil
}

// CurrentSession returns the current session
func (c *Client) CurrentSession() *types.Session {
	return c.session
}

// SetSession sets the current session
func (c *Client) SetSession(session *types.Session) error {
	c.session = session
	return c.saveSession()
}

// GetCurrentSession returns the current session (implements SessionStore interface)
func (c *Client) GetCurrentSession(ctx context.Context) (*types.Session, error) {
	if c.session == nil {
		return nil, fmt.Errorf("no active session")
	}
	if !c.session.IsActive() {
		return nil, fmt.Errorf("session expired")
	}
	return c.session, nil
}

// GetIdentity retrieves an identity by ID (implements SessionStore interface)
func (c *Client) GetIdentity(ctx context.Context, id types.ID) (*types.Identity, error) {
	return c.Identity.GetIdentity(ctx, id)
}

// SaveSession saves the current session (implements SessionStore interface)
func (c *Client) SaveSession(ctx context.Context, session *types.Session) error {
	c.session = session
	return c.saveSession()
}

// ClearSession clears the current session (implements SessionStore interface)
func (c *Client) ClearSession(ctx context.Context) error {
	c.session = nil
	return os.Remove(c.sessionPath)
}

func (c *Client) registerDefaultAutomationHandlers() {
	c.Automation.RegisterHandler("secret:create", automation.SecretCreateHandler(func(ctx context.Context, name, value string) error {
		_, err := c.Secrets.Create(ctx, secrets.CreateSecretOptions{
			Name:      name,
			Value:     []byte(value),
			CreatorID: c.CurrentIdentityID(),
		})
		return err
	}))

	c.Automation.RegisterHandler("org:add_member", automation.OrgAddMemberHandler(func(ctx context.Context, orgID, identityID types.ID, role string) error {
		_, err := c.Org.InviteMember(ctx, org.InviteMemberOptions{
			OrgID:      orgID,
			IdentityID: identityID,
			Role:       role,
			InviterID:  c.CurrentIdentityID(),
		})
		// Auto-accept for automation if possible
		if err == nil {
			_, _ = c.Org.AcceptInvitation(ctx, orgID, identityID)
		}
		return err
	}))

	c.Automation.RegisterHandler("access:grant", automation.AccessGrantHandler(func(ctx context.Context, resourceID types.ID, resourceType string, identityID types.ID, scopes []types.Scope) error {
		_, err := c.Access.Grant(ctx, access.GrantOptions{
			ResourceID:   resourceID,
			ResourceType: resourceType,
			GranteeID:    identityID,
			Scopes:       scopes,
			GrantorID:    c.CurrentIdentityID(),
		})
		return err
	}))

	c.Automation.RegisterFunction("generateToken", func(args ...string) (string, error) {
		if len(args) == 0 {
			return "", fmt.Errorf("generateToken requires at least 1 argument")
		}
		// Mock token generation based on first arg (user_id)
		return fmt.Sprintf("tok_%s_%x", args[0], c.Crypto.HMAC([]byte("token-key"), []byte(args[0]))[:4]), nil
	})
}

// CurrentIdentityID returns the current identity ID
func (c *Client) CurrentIdentityID() types.ID {
	if c.session == nil {
		return ""
	}
	return c.session.IdentityID
}

func (c *Client) loadSession() {
	data, err := os.ReadFile(c.sessionPath)
	if err != nil {
		return
	}

	var session types.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return
	}

	// Rebuild scopes from list
	session.Scopes = types.NewScopeSet(session.ScopeList...)

	// Verify session is still valid
	if session.IsActive() {
		c.session = &session
	}
}

// saveSession saves session to file
func (c *Client) saveSession() error {
	if c.session == nil {
		return nil
	}

	data, err := json.Marshal(c.session)
	if err != nil {
		return err
	}

	return os.WriteFile(c.sessionPath, data, 0600)
}

// Singleton client instance
var defaultClient *Client
var isGUIMode bool

// SetGUIMode sets whether we're running in GUI mode
func SetGUIMode(gui bool) {
	isGUIMode = gui
}

// GetClient returns the default client singleton
func GetClient() (*Client, error) {
	if defaultClient != nil {
		// Update global adapter with current client
		if globalAdapter != nil {
			globalAdapter.SetClient(defaultClient)
		}
		return defaultClient, nil
	}
	// In GUI mode, don't create client until master key is provided
	if isGUIMode {
		return nil, fmt.Errorf("client not initialized - master key required")
	}
	// CLI mode - create client normally
	var err error
	defaultClient, err = NewClient(DefaultConfig())
	// Update global adapter with new client
	if err == nil && globalAdapter != nil {
		globalAdapter.SetClient(defaultClient)
	}
	return defaultClient, err
}

// InitializeClient creates the client with master key already set
func InitializeClient(masterKey []byte) (*Client, error) {
	// Close existing client if any
	if defaultClient != nil {
		defaultClient.Close()
		defaultClient = nil
	}

	// Always create a new client when master key is provided
	// This ensures we don't reuse a client with wrong key
	var err error
	cfg := DefaultConfig()
	cfg.MasterKey = masterKey
	defaultClient, err = NewClient(cfg)

	// Update global adapter with new client
	if err == nil && globalAdapter != nil {
		globalAdapter.SetClient(defaultClient)
	}

	return defaultClient, err
}

// ResetClient clears the default client (for logout)
func ResetClient() {
	if defaultClient != nil {
		defaultClient.Close()
		defaultClient = nil
	}
}

// RequireSession returns error if not logged in
func (c *Client) RequireSession() error {
	if c.session == nil || !c.session.IsActive() {
		return fmt.Errorf("not logged in, run 'secretr auth init' (first-time setup) then 'secretr auth login'")
	}
	return nil
}

// RequireScope checks if current session has required scope
func (c *Client) RequireScope(scope types.Scope) error {
	if err := c.RequireSession(); err != nil {
		return err
	}
	if !c.session.Scopes.Has(scope) {
		return fmt.Errorf("insufficient permissions: requires %s scope", scope)
	}
	return nil
}

// LogAction logs an action to audit
func (c *Client) LogAction(ctx context.Context, eventType, action string, resourceID *types.ID, resourceType string, success bool, details types.Metadata) {
	if c.Audit == nil || c.session == nil {
		return
	}
	c.Audit.Log(ctx, audit.AuditEventInput{
		Type:         eventType,
		Action:       action,
		ActorID:      c.session.IdentityID,
		ActorType:    "identity",
		ResourceID:   resourceID,
		ResourceType: resourceType,
		SessionID:    &c.session.ID,
		Success:      success,
		Details:      details,
	})
}

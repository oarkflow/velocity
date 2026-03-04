// Package identity provides identity management functionality.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/oarkflow/licensing/pkg/device"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrIdentityNotFound    = errors.New("identity: not found")
	ErrIdentityExists      = errors.New("identity: already exists")
	ErrIdentityRevoked     = errors.New("identity: revoked")
	ErrInvalidCredentials  = errors.New("identity: invalid credentials")
	ErrSessionExpired      = errors.New("identity: session expired")
	ErrSessionRevoked      = errors.New("identity: session revoked")
	ErrDeviceNotTrusted    = errors.New("identity: device not trusted")
	ErrMFARequired         = errors.New("identity: MFA verification required")
	ErrRecoveryKeyRequired = errors.New("identity: recovery key required")
)

// Manager handles identity operations
type Manager struct {
	store          *storage.Store
	crypto         *crypto.Engine
	identityStore  *storage.TypedStore[types.Identity]
	deviceStore    *storage.TypedStore[types.Device]
	sessionStore   *storage.TypedStore[types.Session]
	sessionTimeout time.Duration
	idleTimeout    time.Duration
	mfaRequired    bool
}

// ManagerConfig configures the identity manager
type ManagerConfig struct {
	Store          *storage.Store
	SessionTimeout time.Duration
	IdleTimeout    time.Duration
	MFARequired    bool
}

// NewManager creates a new identity manager
func NewManager(cfg ManagerConfig) *Manager {
	cryptoEngine := crypto.NewEngine("")

	timeout := cfg.SessionTimeout
	if timeout == 0 {
		timeout = 24 * time.Hour
	}

	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}

	return &Manager{
		store:          cfg.Store,
		crypto:         cryptoEngine,
		identityStore:  storage.NewTypedStore[types.Identity](cfg.Store, storage.CollectionIdentities),
		deviceStore:    storage.NewTypedStore[types.Device](cfg.Store, storage.CollectionDevices),
		sessionStore:   storage.NewTypedStore[types.Session](cfg.Store, storage.CollectionSessions),
		sessionTimeout: timeout,
		idleTimeout:    idleTimeout,
		mfaRequired:    cfg.MFARequired,
	}
}

// CreateHumanIdentity creates a new human identity
func (m *Manager) CreateHumanIdentity(ctx context.Context, opts CreateHumanOptions) (*types.Identity, error) {
	// Generate ID
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, fmt.Errorf("identity: failed to generate ID: %w", err)
	}

	// Generate key pair
	publicKey, privateKey, err := m.crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("identity: failed to generate key pair: %w", err)
	}
	defer privateKey.Free()

	// Derive encryption key from password
	salt, err := m.crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("identity: failed to generate salt: %w", err)
	}

	encryptionKey, err := m.crypto.DeriveKey([]byte(opts.Password), salt, crypto.KeySize256)
	if err != nil {
		return nil, fmt.Errorf("identity: failed to derive key: %w", err)
	}
	defer encryptionKey.Free()

	// Encrypt private key with derived key
	encryptedPrivKey, err := m.crypto.Encrypt(encryptionKey.Bytes(), privateKey.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("identity: failed to encrypt private key: %w", err)
	}

	// Generate encryption key pair (X25519) for Envelopes
	encPub, encPriv, err := m.crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("identity: failed to generate encryption keys: %w", err)
	}
	defer encPriv.Free()

	encryptedEncPrivKey, err := m.crypto.Encrypt(encryptionKey.Bytes(), encPriv.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("identity: failed to encrypt encryption private key: %w", err)
	}

	now := types.Now()
	fingerprint := m.crypto.Fingerprint(publicKey)

	identity := &types.Identity{
		ID:          id,
		Type:        types.IdentityTypeHuman,
		Name:        opts.Name,
		Email:       opts.Email,
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		CreatedAt:   now,
		UpdatedAt:   now,
		Scopes:      types.NewScopeSet(opts.Scopes...),
		ScopeList:   opts.Scopes,
		Status:      types.StatusActive,
		Metadata: types.Metadata{
			"salt":                         base64.StdEncoding.EncodeToString(salt),
			"encrypted_privkey":            base64.StdEncoding.EncodeToString(encryptedPrivKey),
			"encryption_public_key":        base64.StdEncoding.EncodeToString(encPub),
			"encrypted_encryption_privkey": base64.StdEncoding.EncodeToString(encryptedEncPrivKey),
		},
		Provenance: &types.Provenance{
			CreatedBy:   opts.CreatorID,
			CreatedAt:   now,
			CreatedFrom: opts.DeviceFingerprint,
		},
	}

	if err := m.identityStore.Set(ctx, string(id), identity); err != nil {
		return nil, fmt.Errorf("identity: failed to store identity: %w", err)
	}

	return identity, nil
}

// CreateHumanOptions holds options for creating a human identity
type CreateHumanOptions struct {
	Name              string
	Email             string
	Password          string
	Scopes            []types.Scope
	CreatorID         types.ID
	DeviceFingerprint string
}

// CreateServiceIdentity creates a service/machine identity
func (m *Manager) CreateServiceIdentity(ctx context.Context, opts CreateServiceOptions) (*types.Identity, *ServiceCredentials, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to generate ID: %w", err)
	}

	// Generate API key
	apiKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, apiKey); err != nil {
		return nil, nil, fmt.Errorf("identity: failed to generate API key: %w", err)
	}
	apiKeyStr := base64.URLEncoding.EncodeToString(apiKey)

	// Hash API key for storage
	apiKeyHash := m.crypto.Hash(apiKey)

	// Generate signing key pair
	publicKey, privateKey, err := m.crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("identity: failed to generate key pair: %w", err)
	}
	defer privateKey.Free()

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	identity := &types.Identity{
		ID:          id,
		Type:        types.IdentityTypeService,
		Name:        opts.Name,
		PublicKey:   publicKey,
		Fingerprint: m.crypto.Fingerprint(publicKey),
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   expiresAt,
		Scopes:      types.NewScopeSet(opts.Scopes...),
		ScopeList:   opts.Scopes,
		Status:      types.StatusActive,
		ParentID:    &opts.OwnerID,
		Metadata: types.Metadata{
			"api_key_hash": base64.StdEncoding.EncodeToString(apiKeyHash),
			"description":  opts.Description,
		},
		Provenance: &types.Provenance{
			CreatedBy:   opts.OwnerID,
			CreatedAt:   now,
			CreatedFrom: opts.DeviceFingerprint,
		},
	}

	if err := m.identityStore.Set(ctx, string(id), identity); err != nil {
		return nil, nil, fmt.Errorf("identity: failed to store identity: %w", err)
	}

	credentials := &ServiceCredentials{
		ID:     id,
		APIKey: apiKeyStr,
	}

	return identity, credentials, nil
}

// CreateServiceOptions holds options for creating a service identity
type CreateServiceOptions struct {
	Name              string
	Description       string
	OwnerID           types.ID
	Scopes            []types.Scope
	ExpiresIn         time.Duration
	DeviceFingerprint string
}

// ServiceCredentials contains service authentication credentials
type ServiceCredentials struct {
	ID     types.ID `json:"id"`
	APIKey string   `json:"api_key"`
}

// GetIdentity retrieves an identity by ID
func (m *Manager) GetIdentity(ctx context.Context, id types.ID) (*types.Identity, error) {
	identity, err := m.identityStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrIdentityNotFound
		}
		return nil, err
	}

	// Reconstruct scope set from list
	if identity.ScopeList != nil {
		identity.Scopes = types.NewScopeSet(identity.ScopeList...)
	}

	return identity, nil
}

// GetPrivateKey retrieves the decrypted private key for an identity
func (m *Manager) GetPrivateKey(ctx context.Context, id types.ID, password string) ([]byte, error) {
	identity, err := m.GetIdentity(ctx, id)
	if err != nil {
		return nil, err
	}

	if identity.Type != types.IdentityTypeHuman {
		return nil, errors.New("identity: private key retrieval only supported for human identities")
	}

	// Get salt and encrypted private key
	saltStr, ok := identity.Metadata["salt"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Derive key from password
	derivedKey, err := m.crypto.DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	defer derivedKey.Free()

	// Try to decrypt private key
	encPrivKeyStr, ok := identity.Metadata["encrypted_privkey"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	encPrivKey, err := base64.StdEncoding.DecodeString(encPrivKeyStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	privKey, err := m.crypto.Decrypt(derivedKey.Bytes(), encPrivKey, nil)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return privKey, nil
}

// GetEncryptionPrivateKey retrieves the decrypted encryption private key (X25519)
func (m *Manager) GetEncryptionPrivateKey(ctx context.Context, id types.ID, password string) ([]byte, error) {
	identity, err := m.GetIdentity(ctx, id)
	if err != nil {
		return nil, err
	}

	if identity.Type != types.IdentityTypeHuman {
		return nil, errors.New("identity: private key retrieval only supported for human identities")
	}

	// Get salt
	saltStr, ok := identity.Metadata["salt"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Derive key from password
	derivedKey, err := m.crypto.DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	defer derivedKey.Free()

	// Try to decrypt encryption private key
	encPrivKeyStr, ok := identity.Metadata["encrypted_encryption_privkey"].(string)
	if !ok {
		return nil, errors.New("identity: encryption key not found (identity might be old)")
	}
	encPrivKey, err := base64.StdEncoding.DecodeString(encPrivKeyStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	privKey, err := m.crypto.Decrypt(derivedKey.Bytes(), encPrivKey, nil)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return privKey, nil
}

// ListIdentities lists all identities
func (m *Manager) ListIdentities(ctx context.Context, opts ListOptions) ([]*types.Identity, error) {
	identities, err := m.identityStore.List(ctx, opts.Prefix)
	if err != nil {
		return nil, err
	}

	// Apply filters and reconstruct scopes
	result := make([]*types.Identity, 0, len(identities))
	for _, identity := range identities {
		if opts.Type != "" && identity.Type != opts.Type {
			continue
		}
		if opts.Status != "" && identity.Status != opts.Status {
			continue
		}
		identity.Scopes = types.NewScopeSet(identity.ScopeList...)
		result = append(result, identity)
	}

	return result, nil
}

// ListOptions holds list filter options
type ListOptions struct {
	Prefix string
	Type   types.IdentityType
	Status types.EntityStatus
}

// RevokeIdentity revokes an identity
func (m *Manager) RevokeIdentity(ctx context.Context, id types.ID, revokerID types.ID) error {
	identity, err := m.GetIdentity(ctx, id)
	if err != nil {
		return err
	}

	identity.Status = types.StatusRevoked
	identity.UpdatedAt = types.Now()

	if identity.Provenance != nil {
		identity.Provenance.Chain = append(identity.Provenance.Chain, types.ProvenanceEntry{
			Action:    "revoke",
			ActorID:   revokerID,
			Timestamp: types.Now(),
		})
	}

	// Revoke all active sessions for this identity
	if err := m.RevokeAllSessions(ctx, id); err != nil {
		return fmt.Errorf("identity: failed to revoke sessions: %w", err)
	}

	return m.identityStore.Set(ctx, string(id), identity)
}

// Authenticate authenticates a human identity
func (m *Manager) Authenticate(ctx context.Context, email, password string, deviceID types.ID) (*types.Session, error) {
	// Find identity by email
	identities, err := m.identityStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var identity *types.Identity
	for _, id := range identities {
		if id.Email == email && id.Type == types.IdentityTypeHuman {
			identity = id
			break
		}
	}

	if identity == nil {
		return nil, ErrIdentityNotFound
	}

	if identity.Status != types.StatusActive {
		return nil, ErrIdentityRevoked
	}

	// Get salt and encrypted private key
	saltStr, ok := identity.Metadata["salt"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Derive key from password
	derivedKey, err := m.crypto.DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	defer derivedKey.Free()

	// Try to decrypt private key to verify password
	encPrivKeyStr, ok := identity.Metadata["encrypted_privkey"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	encPrivKey, err := base64.StdEncoding.DecodeString(encPrivKeyStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	_, err = m.crypto.Decrypt(derivedKey.Bytes(), encPrivKey, nil)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verify device if provided
	if deviceID != "" {
		device, err := m.GetDevice(ctx, deviceID)
		if err != nil {
			return nil, ErrDeviceNotTrusted
		}
		if device.Status != types.StatusActive {
			return nil, ErrDeviceNotTrusted
		}
	}

	// Create session
	return m.CreateSession(ctx, CreateSessionOptions{
		IdentityID: identity.ID,
		DeviceID:   deviceID,
		Scopes:     identity.ScopeList,
		Type:       "interactive",
	})
}

// AuthenticateService authenticates a service identity
func (m *Manager) AuthenticateService(ctx context.Context, id types.ID, apiKey string) (*types.Session, error) {
	identity, err := m.GetIdentity(ctx, id)
	if err != nil {
		return nil, err
	}

	if identity.Type != types.IdentityTypeService {
		return nil, ErrInvalidCredentials
	}

	if identity.Status != types.StatusActive {
		return nil, ErrIdentityRevoked
	}

	// Check expiration
	if identity.ExpiresAt != nil && types.Now() > *identity.ExpiresAt {
		return nil, ErrSessionExpired
	}

	// Verify API key
	apiKeyBytes, err := base64.URLEncoding.DecodeString(apiKey)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	storedHashStr, ok := identity.Metadata["api_key_hash"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	storedHash, err := base64.StdEncoding.DecodeString(storedHashStr)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	computedHash := m.crypto.Hash(apiKeyBytes)
	if !security.ConstantTimeCompare(storedHash, computedHash) {
		return nil, ErrInvalidCredentials
	}

	return m.CreateSession(ctx, CreateSessionOptions{
		IdentityID: identity.ID,
		Scopes:     identity.ScopeList,
		Type:       "api",
	})
}

// CreateSession creates a new session
func (m *Manager) CreateSession(ctx context.Context, opts CreateSessionOptions) (*types.Session, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	expiresAt := types.Timestamp(time.Now().Add(m.sessionTimeout).UnixNano())

	session := &types.Session{
		ID:            id,
		IdentityID:    opts.IdentityID,
		DeviceID:      opts.DeviceID,
		Type:          opts.Type,
		Scopes:        types.NewScopeSet(opts.Scopes...),
		ScopeList:     opts.Scopes,
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
		LastActiveAt:  now,
		Fingerprint:   opts.Fingerprint,
		Status:        types.StatusActive,
		MFAVerified:   !m.mfaRequired,
		OfflineIssued: opts.Offline,
	}

	if err := m.sessionStore.Set(ctx, string(id), session); err != nil {
		return nil, fmt.Errorf("identity: failed to store session: %w", err)
	}

	return session, nil
}

// CreateSessionOptions holds session creation options
type CreateSessionOptions struct {
	IdentityID  types.ID
	DeviceID    types.ID
	Scopes      []types.Scope
	Type        string
	Fingerprint string
	Offline     bool
}

// GetSession retrieves a session
func (m *Manager) GetSession(ctx context.Context, id types.ID) (*types.Session, error) {
	session, err := m.sessionStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	session.Scopes = types.NewScopeSet(session.ScopeList...)
	return session, nil
}

// GetCurrentSession returns the current active session (stored locally)
func (m *Manager) GetCurrentSession(ctx context.Context) (*types.Session, error) {
	// In a real implementation, this would read from local session storage
	// For now, get from context or return error
	sessionID, ok := ctx.Value("session_id").(types.ID)
	if !ok || sessionID == "" {
		return nil, ErrSessionExpired
	}
	return m.GetSession(ctx, sessionID)
}

// RefreshSession updates session activity
func (m *Manager) RefreshSession(ctx context.Context, id types.ID) error {
	session, err := m.GetSession(ctx, id)
	if err != nil {
		return err
	}

	if session.Status != types.StatusActive {
		return ErrSessionRevoked
	}

	if session.IsExpired() {
		return ErrSessionExpired
	}

	session.LastActiveAt = types.Now()
	return m.sessionStore.Set(ctx, string(id), session)
}

// RevokeSession revokes a session
func (m *Manager) RevokeSession(ctx context.Context, id types.ID) error {
	session, err := m.GetSession(ctx, id)
	if err != nil {
		return err
	}

	session.Status = types.StatusRevoked
	return m.sessionStore.Set(ctx, string(id), session)
}

// RevokeAllSessions revokes all sessions for an identity
func (m *Manager) RevokeAllSessions(ctx context.Context, identityID types.ID) error {
	sessions, err := m.sessionStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.IdentityID == identityID && session.Status == types.StatusActive {
			session.Status = types.StatusRevoked
			if err := m.sessionStore.Set(ctx, string(session.ID), session); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetActiveSessions returns all active sessions for an identity
func (m *Manager) GetActiveSessions(ctx context.Context, identityID types.ID) ([]*types.Session, error) {
	sessions, err := m.sessionStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := make([]*types.Session, 0)
	for _, session := range sessions {
		if session.IdentityID == identityID && session.Status == types.StatusActive && !session.IsExpired() {
			session.Scopes = types.NewScopeSet(session.ScopeList...)
			result = append(result, session)
		}
	}

	return result, nil
}

// VerifyMFA verifies MFA for a session
func (m *Manager) VerifyMFA(ctx context.Context, sessionID types.ID, token string) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// In a real implementation, verify the MFA token
	// For now, just mark as verified
	session.MFAVerified = true
	return m.sessionStore.Set(ctx, string(sessionID), session)
}

// Device management

// EnrollDevice enrolls a new device
func (m *Manager) EnrollDevice(ctx context.Context, opts EnrollDeviceOptions) (*types.Device, error) {
	// Get device fingerprint as ID
	info, err := device.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	// Use device fingerprint as ID
	id := types.ID(info.Fingerprint)

	// Generate device keys
	publicKey, _, err := m.crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	fingerprint := m.crypto.Fingerprint(publicKey)
	now := types.Now()

	device := &types.Device{
		ID:          id,
		OwnerID:     opts.OwnerID,
		Name:        opts.Name,
		Type:        opts.Type,
		Fingerprint: fingerprint,
		PublicKey:   publicKey,
		TrustScore:  1.0, // Initial trust score
		CreatedAt:   now,
		LastSeenAt:  now,
		Status:      types.StatusActive,
		Metadata:    opts.Metadata,
	}

	if err := m.deviceStore.Set(ctx, string(id), device); err != nil {
		return nil, fmt.Errorf("identity: failed to store device: %w", err)
	}

	return device, nil
}

// EnrollDeviceOptions holds device enrollment options
type EnrollDeviceOptions struct {
	OwnerID  types.ID
	Name     string
	Type     string
	Metadata types.Metadata
}

// GetDevice retrieves a device
func (m *Manager) GetDevice(ctx context.Context, id types.ID) (*types.Device, error) {
	device, err := m.deviceStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, errors.New("device not found")
		}
		return nil, err
	}
	return device, nil
}

// ListDevices lists devices for an owner
func (m *Manager) ListDevices(ctx context.Context, ownerID types.ID) ([]*types.Device, error) {
	devices, err := m.deviceStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := make([]*types.Device, 0)
	for _, device := range devices {
		if device.OwnerID == ownerID {
			result = append(result, device)
		}
	}

	return result, nil
}

// RevokeDevice revokes a device
func (m *Manager) RevokeDevice(ctx context.Context, id types.ID) error {
	device, err := m.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	device.Status = types.StatusRevoked
	return m.deviceStore.Set(ctx, string(id), device)
}

// UpdateTrustScore updates a device's trust score
func (m *Manager) UpdateTrustScore(ctx context.Context, id types.ID, score float64) error {
	device, err := m.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	device.TrustScore = score
	device.LastSeenAt = types.Now()
	return m.deviceStore.Set(ctx, string(id), device)
}

// Attest records device attestation data
func (m *Manager) Attest(ctx context.Context, id types.ID, attestData []byte) error {
	device, err := m.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	device.AttestData = attestData
	device.LastSeenAt = types.Now()
	return m.deviceStore.Set(ctx, string(id), device)
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

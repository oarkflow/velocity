// Package share provides secure sharing functionality.
package share

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrShareNotFound     = errors.New("share: not found")
	ErrShareExpired      = errors.New("share: has expired")
	ErrShareRevoked      = errors.New("share: has been revoked")
	ErrShareAlreadyUsed  = errors.New("share: one-time share already used")
	ErrMaxAccessReached  = errors.New("share: maximum access count reached")
	ErrRecipientMismatch = errors.New("share: recipient mismatch")
	ErrReshareNotAllowed = errors.New("share: resharing not allowed")
)

// Manager handles secure sharing operations
type Manager struct {
	store      *storage.Store
	crypto     *crypto.Engine
	shareStore *storage.TypedStore[types.Share]
	packageStore *storage.TypedStore[OfflinePackage]
}

// OfflinePackage represents an offline sharing package
type OfflinePackage struct {
	ID              types.ID        `json:"id"`
	ShareID         types.ID        `json:"share_id"`
	EncryptedData   []byte          `json:"encrypted_data"`
	EncryptedKey    []byte          `json:"encrypted_key"`
	RecipientPubKey []byte          `json:"recipient_pub_key"`
	Hash            []byte          `json:"hash"`
	Signature       []byte          `json:"signature"`
	CreatedAt       types.Timestamp `json:"created_at"`
	ExpiresAt       types.Timestamp `json:"expires_at"`
}

// ManagerConfig configures the share manager
type ManagerConfig struct {
	Store *storage.Store
}

// NewManager creates a new share manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:        cfg.Store,
		crypto:       crypto.NewEngine(""),
		shareStore:   storage.NewTypedStore[types.Share](cfg.Store, storage.CollectionShares),
		packageStore: storage.NewTypedStore[OfflinePackage](cfg.Store, "offline_packages"),
	}
}

// CreateShare creates a new share
func (m *Manager) CreateShare(ctx context.Context, opts CreateShareOptions) (*types.Share, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	share := &types.Share{
		ID:          id,
		Type:        opts.Type,
		ResourceID:  opts.ResourceID,
		CreatorID:   opts.CreatorID,
		RecipientID: opts.RecipientID,
		CreatedAt:   types.Now(),
		MaxAccess:   opts.MaxAccess,
		AccessCount: 0,
		OneTime:     opts.OneTime,
		Status:      types.StatusActive,
		Metadata:    opts.Metadata,
	}

	if opts.ExpiresIn > 0 {
		expiresAt := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		share.ExpiresAt = &expiresAt
	}

	// For external recipients, store their public key
	if opts.RecipientPubKey != nil {
		share.RecipientKey = opts.RecipientPubKey
	}

	if err := m.shareStore.Set(ctx, string(share.ID), share); err != nil {
		return nil, err
	}

	return share, nil
}

// CreateShareOptions holds share creation options
type CreateShareOptions struct {
	Type            string   // "secret" or "file"
	ResourceID      types.ID
	CreatorID       types.ID
	RecipientID     *types.ID
	RecipientPubKey []byte // For external recipients
	ExpiresIn       time.Duration
	MaxAccess       int
	OneTime         bool
	AllowReshare    bool
	Metadata        types.Metadata
}

// GetShare retrieves a share by ID
func (m *Manager) GetShare(ctx context.Context, id types.ID) (*types.Share, error) {
	share, err := m.shareStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrShareNotFound
	}
	return share, nil
}

// ListShares lists shares for a user
func (m *Manager) ListShares(ctx context.Context, opts ListSharesOptions) ([]*types.Share, error) {
	shares, err := m.shareStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var result []*types.Share
	for _, s := range shares {
		if opts.CreatorID != "" && s.CreatorID != opts.CreatorID {
			continue
		}
		if opts.RecipientID != "" && (s.RecipientID == nil || *s.RecipientID != opts.RecipientID) {
			continue
		}
		if opts.ResourceID != "" && s.ResourceID != opts.ResourceID {
			continue
		}
		if !opts.IncludeExpired && s.Status != types.StatusActive {
			continue
		}
		result = append(result, s)
	}
	return result, nil
}

// ListSharesOptions holds list options
type ListSharesOptions struct {
	CreatorID      types.ID
	RecipientID    types.ID
	ResourceID     types.ID
	IncludeExpired bool
}

// AccessShare accesses a share (validates and records access)
func (m *Manager) AccessShare(ctx context.Context, shareID types.ID, accessorID types.ID) (*ShareAccess, error) {
	share, err := m.GetShare(ctx, shareID)
	if err != nil {
		return nil, err
	}

	// Check status
	if share.Status == types.StatusRevoked {
		return nil, ErrShareRevoked
	}

	// Check expiration
	if share.ExpiresAt != nil && types.Now() > *share.ExpiresAt {
		return nil, ErrShareExpired
	}

	// Check one-time
	if share.OneTime && share.AccessCount > 0 {
		return nil, ErrShareAlreadyUsed
	}

	// Check max access
	if share.MaxAccess > 0 && share.AccessCount >= share.MaxAccess {
		return nil, ErrMaxAccessReached
	}

	// Check recipient if specified
	if share.RecipientID != nil && *share.RecipientID != accessorID {
		return nil, ErrRecipientMismatch
	}

	// Record access
	share.AccessCount++
	accessedAt := types.Now()
	share.AccessedAt = &accessedAt

	if err := m.shareStore.Set(ctx, string(share.ID), share); err != nil {
		return nil, err
	}

	return &ShareAccess{
		ShareID:    shareID,
		ResourceID: share.ResourceID,
		Type:       share.Type,
		AccessedAt: time.Now(),
	}, nil
}

// ShareAccess represents share access result
type ShareAccess struct {
	ShareID    types.ID  `json:"share_id"`
	ResourceID types.ID  `json:"resource_id"`
	Type       string    `json:"type"`
	AccessedAt time.Time `json:"accessed_at"`
}

// RevokeShare revokes a share
func (m *Manager) RevokeShare(ctx context.Context, shareID types.ID, revokerID types.ID) error {
	share, err := m.GetShare(ctx, shareID)
	if err != nil {
		return err
	}

	// Only creator can revoke
	if share.CreatorID != revokerID {
		return errors.New("share: only creator can revoke")
	}

	share.Status = types.StatusRevoked
	revokedAt := types.Now()
	share.RevokedAt = &revokedAt

	return m.shareStore.Set(ctx, string(share.ID), share)
}

// RecordProofOfReceipt records that recipient has confirmed receipt
func (m *Manager) RecordProofOfReceipt(ctx context.Context, shareID types.ID, recipientID types.ID, signature []byte) error {
	share, err := m.GetShare(ctx, shareID)
	if err != nil {
		return err
	}

	// Verify recipient
	if share.RecipientID != nil && *share.RecipientID != recipientID {
		return ErrRecipientMismatch
	}

	share.ProofOfReceipt = signature
	return m.shareStore.Set(ctx, string(share.ID), share)
}

// VerifyProofOfReceipt verifies the proof of receipt
func (m *Manager) VerifyProofOfReceipt(ctx context.Context, shareID types.ID, recipientPubKey []byte) error {
	share, err := m.GetShare(ctx, shareID)
	if err != nil {
		return err
	}

	if share.ProofOfReceipt == nil {
		return errors.New("share: no proof of receipt recorded")
	}

	// Create verification message
	message := []byte(string(shareID) + ":received")

	return m.crypto.Verify(recipientPubKey, message, share.ProofOfReceipt)
}

// CreateOfflinePackage creates an offline sharing package
func (m *Manager) CreateOfflinePackage(ctx context.Context, opts OfflinePackageOptions) (*OfflinePackage, error) {
	share, err := m.GetShare(ctx, opts.ShareID)
	if err != nil {
		return nil, err
	}

	// Generate package encryption key
	packageKey, err := m.crypto.GenerateKey(crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer packageKey.Free()

	// Encrypt the resource data
	encryptedData, err := m.crypto.Encrypt(packageKey.Bytes(), opts.ResourceData, nil)
	if err != nil {
		return nil, err
	}

	// Encrypt the package key for the recipient
	encryptedKey, err := m.crypto.Encrypt(opts.RecipientPubKey[:32], packageKey.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	id, _ := m.crypto.GenerateRandomID()
	hash := m.crypto.Hash(encryptedData)

	pkg := &OfflinePackage{
		ID:              id,
		ShareID:         share.ID,
		EncryptedData:   encryptedData,
		EncryptedKey:    encryptedKey,
		RecipientPubKey: opts.RecipientPubKey,
		Hash:            hash,
		CreatedAt:       types.Now(),
	}

	if opts.ExpiresIn > 0 {
		pkg.ExpiresAt = types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
	}

	// Sign the package
	if opts.SignerKey != nil {
		message, _ := json.Marshal(struct {
			ShareID types.ID `json:"share_id"`
			Hash    []byte   `json:"hash"`
		}{share.ID, hash})
		sig, _ := m.crypto.Sign(opts.SignerKey, message)
		pkg.Signature = sig
	}

	if err := m.packageStore.Set(ctx, string(pkg.ID), pkg); err != nil {
		return nil, err
	}

	return pkg, nil
}

// OfflinePackageOptions holds offline package creation options
type OfflinePackageOptions struct {
	ShareID         types.ID
	ResourceData    []byte
	RecipientPubKey []byte
	ExpiresIn       time.Duration
	SignerKey       []byte
}

// ExportOfflinePackage exports a package for offline transfer
func (m *Manager) ExportOfflinePackage(ctx context.Context, packageID types.ID) ([]byte, error) {
	pkg, err := m.packageStore.Get(ctx, string(packageID))
	if err != nil {
		return nil, errors.New("share: package not found")
	}

	return json.Marshal(pkg)
}

// ImportOfflinePackage imports and validates an offline package
func (m *Manager) ImportOfflinePackage(ctx context.Context, data []byte, recipientPrivKey []byte) (*ImportResult, error) {
	var pkg OfflinePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, errors.New("share: invalid package format")
	}

	// Check expiration
	if pkg.ExpiresAt > 0 && types.Now() > pkg.ExpiresAt {
		return nil, ErrShareExpired
	}

	// Verify hash
	actualHash := m.crypto.Hash(pkg.EncryptedData)
	if !bytesEqual(actualHash, pkg.Hash) {
		return nil, errors.New("share: package integrity check failed")
	}

	// Decrypt the package key
	packageKey, err := m.crypto.Decrypt(recipientPrivKey[:32], pkg.EncryptedKey, nil)
	if err != nil {
		return nil, errors.New("share: failed to decrypt package key")
	}

	// Decrypt the data
	decryptedData, err := m.crypto.Decrypt(packageKey, pkg.EncryptedData, nil)
	if err != nil {
		return nil, errors.New("share: failed to decrypt data")
	}

	return &ImportResult{
		ShareID:      pkg.ShareID,
		Data:         decryptedData,
		Verified:     true,
		ImportedAt:   time.Now(),
	}, nil
}

// ImportResult represents import result
type ImportResult struct {
	ShareID    types.ID  `json:"share_id"`
	Data       []byte    `json:"data"`
	Verified   bool      `json:"verified"`
	ImportedAt time.Time `json:"imported_at"`
}

// Resharing

// Reshare creates a new share from an existing share
func (m *Manager) Reshare(ctx context.Context, originalShareID types.ID, opts ReshareOptions) (*types.Share, error) {
	original, err := m.GetShare(ctx, originalShareID)
	if err != nil {
		return nil, err
	}

	// Check if resharing is allowed
	if original.Metadata != nil {
		if allowed, ok := original.Metadata["allow_reshare"].(bool); ok && !allowed {
			return nil, ErrReshareNotAllowed
		}
	}

	// Create new share with reduced permissions
	newShare, err := m.CreateShare(ctx, CreateShareOptions{
		Type:        original.Type,
		ResourceID:  original.ResourceID,
		CreatorID:   opts.ResharerID,
		RecipientID: opts.NewRecipientID,
		ExpiresIn:   opts.ExpiresIn,
		MaxAccess:   opts.MaxAccess,
		OneTime:     opts.OneTime,
		AllowReshare: false, // Don't allow further resharing
		Metadata: types.Metadata{
			"original_share_id": string(originalShareID),
			"reshared_by":       string(opts.ResharerID),
		},
	})
	if err != nil {
		return nil, err
	}

	return newShare, nil
}

// ReshareOptions holds reshare options
type ReshareOptions struct {
	ResharerID     types.ID
	NewRecipientID *types.ID
	ExpiresIn      time.Duration
	MaxAccess      int
	OneTime        bool
}

// External Collaborator Isolation

// CreateExternalShare creates a share for an external collaborator
func (m *Manager) CreateExternalShare(ctx context.Context, opts ExternalShareOptions) (*types.Share, string, error) {
	// Generate a one-time access token
	token, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, "", err
	}

	share, err := m.CreateShare(ctx, CreateShareOptions{
		Type:       opts.Type,
		ResourceID: opts.ResourceID,
		CreatorID:  opts.CreatorID,
		ExpiresIn:  opts.ExpiresIn,
		MaxAccess:  1, // External shares are one-time by default
		OneTime:    true,
		Metadata: types.Metadata{
			"external":     true,
			"access_token": string(token),
			"recipient_email": opts.RecipientEmail,
		},
	})
	if err != nil {
		return nil, "", err
	}

	// Return the share and access URL/token
	accessToken := string(share.ID) + ":" + string(token)
	return share, accessToken, nil
}

// ExternalShareOptions holds external share options
type ExternalShareOptions struct {
	Type           string
	ResourceID     types.ID
	CreatorID      types.ID
	RecipientEmail string
	ExpiresIn      time.Duration
}

// AccessExternalShare accesses an external share using token
func (m *Manager) AccessExternalShare(ctx context.Context, shareID types.ID, token string) (*ShareAccess, error) {
	share, err := m.GetShare(ctx, shareID)
	if err != nil {
		return nil, err
	}

	// Verify token
	if share.Metadata == nil {
		return nil, errors.New("share: invalid share")
	}

	expectedToken, ok := share.Metadata["access_token"].(string)
	if !ok || expectedToken != token {
		return nil, errors.New("share: invalid access token")
	}

	// Use special accessor ID for external access
	return m.AccessShare(ctx, shareID, types.ID("external:"+token[:8]))
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

// Helper
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

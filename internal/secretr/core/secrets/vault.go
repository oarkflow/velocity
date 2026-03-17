// Package secrets provides secret vault functionality.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrSecretNotFound  = errors.New("secrets: not found")
	ErrSecretExists    = errors.New("secrets: already exists")
	ErrSecretImmutable = errors.New("secrets: cannot modify immutable secret")
	ErrSecretExpired   = errors.New("secrets: secret has expired")
	ErrSecretReadOnce  = errors.New("secrets: secret can only be read once")
	ErrAccessDenied    = errors.New("secrets: access denied")
	ErrVersionNotFound = errors.New("secrets: version not found")
	ErrMFARequired     = errors.New("secrets: multi-factor authentication required")
)

// Vault manages encrypted secrets
type Vault struct {
	store        *storage.Store
	crypto       *crypto.Engine
	envelope     *crypto.EnvelopeEncryption
	secretStore  *storage.TypedStore[types.Secret]
	versionStore *storage.TypedStore[types.SecretVersion]
	auditStore   *storage.AuditStore
	keyManager   KeyProvider
}

// KeyProvider provides encryption keys
type KeyProvider interface {
	GetKey(ctx context.Context, id types.ID) ([]byte, error)
	GetCurrentKeyID(ctx context.Context) (types.ID, error)
}

// VaultConfig configures the vault
type VaultConfig struct {
	Store      *storage.Store
	KeyManager KeyProvider
}

// NewVault creates a new secret vault
func NewVault(cfg VaultConfig) *Vault {
	cryptoEngine := crypto.NewEngine("")
	return &Vault{
		store:        cfg.Store,
		crypto:       cryptoEngine,
		envelope:     crypto.NewEnvelopeEncryption(cryptoEngine),
		secretStore:  storage.NewTypedStore[types.Secret](cfg.Store, storage.CollectionSecrets),
		versionStore: storage.NewTypedStore[types.SecretVersion](cfg.Store, storage.CollectionSecretVersions),
		auditStore:   storage.NewAuditStore(cfg.Store),
		keyManager:   cfg.KeyManager,
	}
}

// Create creates a new secret
func (v *Vault) Create(ctx context.Context, opts CreateSecretOptions) (*types.Secret, error) {
	// Handle dot notation for nested secrets
	if strings.Contains(opts.Name, ".") {
		return v.setNested(ctx, opts.Name, opts.Value, opts)
	}

	// Check if secret already exists
	existing, _ := v.secretStore.Get(ctx, opts.Name)
	if existing != nil && existing.Status != types.StatusRevoked {
		return nil, ErrSecretExists
	}

	id, err := v.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Get encryption key
	keyID, err := v.keyManager.GetCurrentKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to get key: %w", err)
	}
	key, err := v.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to get key: %w", err)
	}
	defer security.Zeroize(key)

	// Encrypt the secret value
	encryptedData, err := v.crypto.Encrypt(key, opts.Value, []byte(opts.Name))
	if err != nil {
		return nil, fmt.Errorf("secrets: encryption failed: %w", err)
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	secret := &types.Secret{
		ID:            id,
		Name:          opts.Name,
		Type:          opts.Type,
		Version:       1,
		Environment:   opts.Environment,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     expiresAt,
		AccessCount:   0,
		ReadOnce:      opts.ReadOnce,
		Immutable:     opts.Immutable,
		RequireMFA:    opts.RequireMFA,
		Status:        types.StatusActive,
		Metadata:      opts.Metadata,
		EncryptedData: encryptedData,
		KeyID:         keyID,
		Provenance: &types.Provenance{
			CreatedBy:   opts.CreatorID,
			CreatedAt:   now,
			CreatedFrom: opts.DeviceFingerprint,
		},
	}

	if err := v.secretStore.Set(ctx, opts.Name, secret); err != nil {
		return nil, err
	}

	// Store initial version
	version := &types.SecretVersion{
		SecretID:      id,
		Version:       1,
		CreatedAt:     now,
		CreatedBy:     opts.CreatorID,
		EncryptedData: encryptedData,
		KeyID:         keyID,
		Hash:          v.crypto.Hash(opts.Value),
	}
	versionKey := fmt.Sprintf("%s:v%d", opts.Name, 1)
	if err := v.versionStore.Set(ctx, versionKey, version); err != nil {
		return nil, err
	}

	return secret, nil
}

// CreateSecretOptions holds options for creating a secret
type CreateSecretOptions struct {
	Name              string
	Type              types.SecretType
	Value             []byte
	Environment       string
	ExpiresIn         time.Duration
	ReadOnce          bool
	Immutable         bool
	RequireMFA        bool
	Metadata          types.Metadata
	CreatorID         types.ID
	DeviceFingerprint string
}

// Get retrieves a secret's value
func (v *Vault) Get(ctx context.Context, name string, accessorID types.ID, mfaVerified bool) ([]byte, error) {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) && strings.Contains(name, ".") {
			return v.getNested(ctx, name, accessorID, mfaVerified)
		}
		return nil, err
	}

	// Check if expired
	if secret.ExpiresAt != nil && types.Now() > *secret.ExpiresAt {
		return nil, ErrSecretExpired
	}

	// Check if already read (for read-once secrets)
	if secret.ReadOnce && secret.AccessCount > 0 {
		return nil, ErrSecretReadOnce
	}

	// Check MFA requirement
	if secret.RequireMFA && !mfaVerified {
		return nil, ErrMFARequired
	}

	// Get decryption key
	key, err := v.keyManager.GetKey(ctx, secret.KeyID)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to get key: %w", err)
	}
	defer security.Zeroize(key)

	// Decrypt
	plaintext, err := v.crypto.Decrypt(key, secret.EncryptedData, []byte(secret.Name))
	if err != nil {
		return nil, fmt.Errorf("secrets: decryption failed: %w", err)
	}

	// Update access count
	secret.AccessCount++
	secret.UpdatedAt = types.Now()
	if err := v.secretStore.Set(ctx, name, secret); err != nil {
		security.Zeroize(plaintext)
		return nil, err
	}

	// For read-once secrets, mark as expired after access
	if secret.ReadOnce {
		secret.Status = types.StatusExpired
		v.secretStore.Set(ctx, name, secret)
	}

	return plaintext, nil
}

// GetMetadata retrieves secret metadata without decrypting
func (v *Vault) GetMetadata(ctx context.Context, name string) (*types.Secret, error) {
	secret, err := v.secretStore.Get(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, err
	}

	if secret.Status == types.StatusRevoked {
		return nil, ErrSecretNotFound
	}

	return secret, nil
}

// Update updates a secret's value (creates new version)
func (v *Vault) Update(ctx context.Context, name string, newValue []byte, updaterID types.ID) (*types.Secret, error) {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	if secret.Immutable {
		return nil, ErrSecretImmutable
	}

	// Get encryption key
	keyID, err := v.keyManager.GetCurrentKeyID(ctx)
	if err != nil {
		return nil, err
	}
	key, err := v.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(key)

	// Encrypt new value
	encryptedData, err := v.crypto.Encrypt(key, newValue, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("secrets: encryption failed: %w", err)
	}

	// Update secret
	secret.Version++
	secret.UpdatedAt = types.Now()
	secret.EncryptedData = encryptedData
	secret.KeyID = keyID

	if secret.Provenance != nil {
		secret.Provenance.Chain = append(secret.Provenance.Chain, types.ProvenanceEntry{
			Action:    "update",
			ActorID:   updaterID,
			Timestamp: types.Now(),
		})
	}

	if err := v.secretStore.Set(ctx, name, secret); err != nil {
		return nil, err
	}

	// Store new version
	version := &types.SecretVersion{
		SecretID:      secret.ID,
		Version:       secret.Version,
		CreatedAt:     types.Now(),
		CreatedBy:     updaterID,
		EncryptedData: encryptedData,
		KeyID:         keyID,
		Hash:          v.crypto.Hash(newValue),
	}
	versionKey := fmt.Sprintf("%s:v%d", name, secret.Version)
	if err := v.versionStore.Set(ctx, versionKey, version); err != nil {
		return nil, err
	}

	return secret, nil
}

// Delete deletes a secret
func (v *Vault) Delete(ctx context.Context, name string, deleterID types.ID) error {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		return err
	}

	secret.Status = types.StatusRevoked
	secret.UpdatedAt = types.Now()

	if secret.Provenance != nil {
		secret.Provenance.Chain = append(secret.Provenance.Chain, types.ProvenanceEntry{
			Action:    "delete",
			ActorID:   deleterID,
			Timestamp: types.Now(),
		})
	}

	return v.secretStore.Set(ctx, name, secret)
}

// List lists all secrets
func (v *Vault) List(ctx context.Context, opts ListSecretsOptions) ([]*types.Secret, error) {
	secrets, err := v.secretStore.List(ctx, opts.Prefix)
	if err != nil {
		return nil, err
	}

	result := make([]*types.Secret, 0, len(secrets))
	for _, secret := range secrets {
		if secret.Status == types.StatusRevoked && !opts.IncludeDeleted {
			continue
		}
		if opts.Environment != "" && secret.Environment != opts.Environment {
			continue
		}
		if opts.Type != "" && secret.Type != opts.Type {
			continue
		}
		result = append(result, secret)
	}

	return result, nil
}

// ListSecretsOptions holds list options
type ListSecretsOptions struct {
	Prefix         string
	Environment    string
	Type           types.SecretType
	IncludeDeleted bool
}

// GetVersion retrieves a specific version
func (v *Vault) GetVersion(ctx context.Context, name string, version int, accessorID types.ID, mfaVerified bool) ([]byte, error) {
	versionKey := fmt.Sprintf("%s:v%d", name, version)
	secretVersion, err := v.versionStore.Get(ctx, versionKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrVersionNotFound
		}
		return nil, err
	}

	// Check main secret metadata for MFA requirement
	secret, err := v.GetMetadata(ctx, name)
	if err == nil {
		if secret.RequireMFA && !mfaVerified {
			return nil, ErrMFARequired
		}
	}

	key, err := v.keyManager.GetKey(ctx, secretVersion.KeyID)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(key)

	return v.crypto.Decrypt(key, secretVersion.EncryptedData, []byte(name))
}

// GetHistory retrieves version history
func (v *Vault) GetHistory(ctx context.Context, name string) ([]*types.SecretVersion, error) {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	versions := make([]*types.SecretVersion, 0, secret.Version)
	for i := 1; i <= secret.Version; i++ {
		versionKey := fmt.Sprintf("%s:v%d", name, i)
		version, err := v.versionStore.Get(ctx, versionKey)
		if err != nil {
			continue
		}
		// Don't include encrypted data in history
		version.EncryptedData = nil
		versions = append(versions, version)
	}

	return versions, nil
}

// Rotate rotates a secret's value
func (v *Vault) Rotate(ctx context.Context, name string, generator SecretGenerator, rotatorID types.ID) (*types.Secret, error) {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	if secret.Immutable {
		return nil, ErrSecretImmutable
	}

	// Generate new value
	newValue, err := generator.Generate(secret.Type)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to generate new value: %w", err)
	}
	defer security.Zeroize(newValue)

	return v.Update(ctx, name, newValue, rotatorID)
}

// SecretGenerator generates secret values
type SecretGenerator interface {
	Generate(secretType types.SecretType) ([]byte, error)
}

// Export exports secrets for offline/backup
func (v *Vault) Export(ctx context.Context, names []string, exportKey []byte) ([]byte, error) {
	exports := make(map[string]exportedSecret)

	for _, name := range names {
		secret, err := v.GetMetadata(ctx, name)
		if err != nil {
			continue
		}

		key, err := v.keyManager.GetKey(ctx, secret.KeyID)
		if err != nil {
			continue
		}

		plaintext, err := v.crypto.Decrypt(key, secret.EncryptedData, []byte(name))
		security.Zeroize(key)
		if err != nil {
			continue
		}

		exports[name] = exportedSecret{
			Value:       plaintext,
			Type:        secret.Type,
			Environment: secret.Environment,
			Metadata:    secret.Metadata,
		}
	}

	exportData, err := json.Marshal(exports)
	if err != nil {
		return nil, err
	}

	// Encrypt export with provided key
	encrypted, err := v.crypto.Encrypt(exportKey, exportData, []byte("export"))
	security.Zeroize(exportData)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

type exportedSecret struct {
	Value       []byte           `json:"value"`
	Type        types.SecretType `json:"type"`
	Environment string           `json:"environment"`
	Metadata    types.Metadata   `json:"metadata"`
}

// Import imports secrets from export
func (v *Vault) Import(ctx context.Context, encryptedExport []byte, importKey []byte, importerID types.ID) error {
	exportData, err := v.crypto.Decrypt(importKey, encryptedExport, []byte("export"))
	if err != nil {
		return fmt.Errorf("secrets: failed to decrypt export: %w", err)
	}
	defer security.Zeroize(exportData)

	var exports map[string]exportedSecret
	if err := json.Unmarshal(exportData, &exports); err != nil {
		return fmt.Errorf("secrets: invalid export format: %w", err)
	}

	for name, exported := range exports {
		_, err := v.Create(ctx, CreateSecretOptions{
			Name:        name,
			Type:        exported.Type,
			Value:       exported.Value,
			Environment: exported.Environment,
			Metadata:    exported.Metadata,
			CreatorID:   importerID,
		})
		if err != nil && !errors.Is(err, ErrSecretExists) {
			return fmt.Errorf("secrets: failed to import %s: %w", name, err)
		}
	}

	return nil
}

// Shred cryptographically destroys a secret
func (v *Vault) Shred(ctx context.Context, name string, shredderID types.ID, signerPrivKey []byte) (*crypto.KeyDestructionProof, error) {
	secret, err := v.GetMetadata(ctx, name)
	if err != nil {
		return nil, err
	}

	// Get the key to create destruction proof
	key, err := v.keyManager.GetKey(ctx, secret.KeyID)
	if err != nil {
		return nil, err
	}

	// Create destruction proof
	proof, err := v.crypto.CreateDestructionProof(secret.ID, key, shredderID, signerPrivKey)
	security.Zeroize(key)
	if err != nil {
		return nil, err
	}

	// Delete all versions
	for i := 1; i <= secret.Version; i++ {
		versionKey := fmt.Sprintf("%s:v%d", name, i)
		v.store.Delete(ctx, storage.CollectionSecretVersions, versionKey)
	}

	// Delete the secret
	v.store.Delete(ctx, storage.CollectionSecrets, name)

	return proof, nil
}

// Close cleans up resources
func (v *Vault) Close() error {
	return v.crypto.Close()
}

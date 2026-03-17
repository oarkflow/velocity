// Package keys provides key management functionality.
package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrKeyNotFound        = errors.New("keys: not found")
	ErrKeyExpired         = errors.New("keys: key has expired")
	ErrKeyDestroyed       = errors.New("keys: key has been destroyed")
	ErrKeyRevoked         = errors.New("keys: key has been revoked")
	ErrInvalidShard       = errors.New("keys: invalid recovery shard")
	ErrInsufficientShards = errors.New("keys: insufficient shards for recovery")
)

// Manager handles cryptographic key lifecycle
type Manager struct {
	store            *storage.Store
	crypto           *crypto.Engine
	keyStore         *storage.TypedStore[types.Key]
	masterKey        *security.SecureBytes
	currentKeyID     types.ID
	mu               sync.RWMutex
	rotationInterval time.Duration
}

// ManagerConfig configures the key manager
type ManagerConfig struct {
	Store            *storage.Store
	MasterKey        []byte
	RotationInterval time.Duration
}

// NewManager creates a new key manager
func NewManager(cfg ManagerConfig) (*Manager, error) {
	// Use provided master key or get from store
	masterKeyBytes := cfg.MasterKey
	if len(masterKeyBytes) == 0 {
		// Fallback to store master key if no key provided
		masterKeyBytes = cfg.Store.MasterKey()
	}
	
	masterKey, err := security.NewSecureBytesFromSlice(masterKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to secure master key: %w", err)
	}

	m := &Manager{
		store:            cfg.Store,
		crypto:           crypto.NewEngine(""),
		keyStore:         storage.NewTypedStore[types.Key](cfg.Store, storage.CollectionKeys),
		masterKey:        masterKey,
		rotationInterval: cfg.RotationInterval,
	}

	if err := m.initializeCurrentKey(context.Background()); err != nil {
		masterKey.Free()
		return nil, err
	}

	return m, nil
}

func (m *Manager) initializeCurrentKey(ctx context.Context) error {
	keys, err := m.keyStore.List(ctx, "")
	if err != nil {
		return err
	}

	var latestKey *types.Key
	for _, key := range keys {
		if key.Type == types.KeyTypeEncryption && key.Status == types.StatusActive {
			if latestKey == nil || key.CreatedAt > latestKey.CreatedAt {
				latestKey = key
			}
		}
	}

	if latestKey != nil {
		m.currentKeyID = latestKey.ID
		return nil
	}

	key, err := m.GenerateKey(ctx, GenerateKeyOptions{
		Type:    types.KeyTypeEncryption,
		Purpose: types.KeyPurposeEncrypt,
	})
	if err != nil {
		return err
	}

	m.currentKeyID = key.ID
	return nil
}

// GenerateKeyOptions holds key generation options
type GenerateKeyOptions struct {
	Type           types.KeyType
	Purpose        types.KeyPurpose
	ExpiresIn      time.Duration
	ParentKeyID    *types.ID
	DeviceID       *types.ID
	SessionID      *types.ID
	HardwareBacked bool
	Metadata       types.Metadata
}

// GenerateKey generates a new key
func (m *Manager) GenerateKey(ctx context.Context, opts GenerateKeyOptions) (*types.Key, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	keyMaterial, err := m.crypto.GenerateKey(crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer keyMaterial.Free()

	encryptedMaterial, err := m.crypto.Encrypt(m.masterKey.Bytes(), keyMaterial.Bytes(), []byte(id))
	if err != nil {
		return nil, fmt.Errorf("keys: failed to encrypt key: %w", err)
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	key := &types.Key{
		ID:             id,
		Type:           opts.Type,
		Algorithm:      crypto.AlgorithmAES256GCM,
		Version:        1,
		Purpose:        opts.Purpose,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
		Status:         types.StatusActive,
		ParentKeyID:    opts.ParentKeyID,
		DeviceID:       opts.DeviceID,
		SessionID:      opts.SessionID,
		HardwareBacked: opts.HardwareBacked,
		Material:       encryptedMaterial,
		Metadata:       opts.Metadata,
	}

	if err := m.keyStore.Set(ctx, string(id), key); err != nil {
		return nil, err
	}

	return key, nil
}

// GetKey retrieves decrypted key material
func (m *Manager) GetKey(ctx context.Context, id types.ID) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, err := m.keyStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	if key.Status == types.StatusRevoked {
		return nil, ErrKeyRevoked
	}
	if key.DestroyedAt != nil {
		return nil, ErrKeyDestroyed
	}
	if key.ExpiresAt != nil && types.Now() > *key.ExpiresAt {
		return nil, ErrKeyExpired
	}

	return m.crypto.Decrypt(m.masterKey.Bytes(), key.Material, []byte(id))
}

// GetCurrentKeyID returns the current encryption key ID
func (m *Manager) GetCurrentKeyID(ctx context.Context) (types.ID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.currentKeyID == "" {
		return "", errors.New("keys: no current key available")
	}
	return m.currentKeyID, nil
}

// GetKeyMetadata retrieves key metadata without material
func (m *Manager) GetKeyMetadata(ctx context.Context, id types.ID) (*types.Key, error) {
	key, err := m.keyStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	key.Material = nil
	return key, nil
}

// ListKeysOptions holds list options
type ListKeysOptions struct {
	Type   types.KeyType
	Status types.EntityStatus
}

// ListKeys lists all keys
func (m *Manager) ListKeys(ctx context.Context, opts ListKeysOptions) ([]*types.Key, error) {
	keys, err := m.keyStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := make([]*types.Key, 0, len(keys))
	for _, key := range keys {
		if opts.Type != "" && key.Type != opts.Type {
			continue
		}
		if opts.Status != "" && key.Status != opts.Status {
			continue
		}
		key.Material = nil
		result = append(result, key)
	}
	return result, nil
}

// RotateKey rotates a key
func (m *Manager) RotateKey(ctx context.Context, id types.ID) (*types.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldKey, err := m.keyStore.Get(ctx, string(id))
	if err != nil {
		return nil, err
	}

	newMaterial, err := m.crypto.GenerateKey(crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer newMaterial.Free()

	encryptedMaterial, err := m.crypto.Encrypt(m.masterKey.Bytes(), newMaterial.Bytes(), []byte(id))
	if err != nil {
		return nil, err
	}

	now := types.Now()
	oldKey.Version++
	oldKey.RotatedAt = &now
	oldKey.Material = encryptedMaterial

	if err := m.keyStore.Set(ctx, string(id), oldKey); err != nil {
		return nil, err
	}

	if id == m.currentKeyID {
		newKey, err := m.GenerateKey(ctx, GenerateKeyOptions{
			Type:    oldKey.Type,
			Purpose: oldKey.Purpose,
		})
		if err != nil {
			return nil, err
		}
		m.currentKeyID = newKey.ID
	}

	return oldKey, nil
}

// DestroyKey destroys a key with proof
func (m *Manager) DestroyKey(ctx context.Context, id types.ID, destroyerID types.ID, signerPrivKey []byte) (*crypto.KeyDestructionProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := m.keyStore.Get(ctx, string(id))
	if err != nil {
		return nil, err
	}

	material, err := m.crypto.Decrypt(m.masterKey.Bytes(), key.Material, []byte(id))
	if err != nil {
		return nil, err
	}

	proof, err := m.crypto.CreateDestructionProof(id, material, destroyerID, signerPrivKey)
	security.Zeroize(material)
	if err != nil {
		return nil, err
	}

	now := types.Now()
	key.Status = types.StatusRevoked
	key.DestroyedAt = &now
	key.Material = nil

	if err := m.keyStore.Set(ctx, string(id), key); err != nil {
		return nil, err
	}

	return proof, nil
}

// DeriveKeyOptions holds derivation options
type DeriveKeyOptions struct {
	Purpose   types.KeyPurpose
	ExpiresIn time.Duration
	DeviceID  *types.ID
	SessionID *types.ID
}

// DeriveKey derives a key from parent key
func (m *Manager) DeriveKey(ctx context.Context, parentID types.ID, info []byte, opts DeriveKeyOptions) (*types.Key, error) {
	parentMaterial, err := m.GetKey(ctx, parentID)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(parentMaterial)

	salt, err := m.crypto.GenerateSalt()
	if err != nil {
		return nil, err
	}

	derivedMaterial, err := m.crypto.DeriveKeyHKDF(parentMaterial, salt, info, crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer derivedMaterial.Free()

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	encryptedMaterial, err := m.crypto.Encrypt(m.masterKey.Bytes(), derivedMaterial.Bytes(), []byte(id))
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	key := &types.Key{
		ID:          id,
		Type:        types.KeyTypeDerived,
		Algorithm:   crypto.AlgorithmHKDF,
		Version:     1,
		Purpose:     opts.Purpose,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		Status:      types.StatusActive,
		ParentKeyID: &parentID,
		DeviceID:    opts.DeviceID,
		SessionID:   opts.SessionID,
		Material:    encryptedMaterial,
		Metadata: types.Metadata{
			"salt": base64.StdEncoding.EncodeToString(salt),
			"info": base64.StdEncoding.EncodeToString(info),
		},
	}

	if err := m.keyStore.Set(ctx, string(id), key); err != nil {
		return nil, err
	}

	return key, nil
}

// KeyShard represents a key recovery shard
type KeyShard struct {
	ID        types.ID `json:"id"`
	KeyID     types.ID `json:"key_id"`
	Index     int      `json:"index"`
	Threshold int      `json:"threshold"`
	Total     int      `json:"total"`
	Data      []byte   `json:"data"`
	Hash      []byte   `json:"hash"`
}

// SplitKey implements M-of-N recovery
func (m *Manager) SplitKey(ctx context.Context, id types.ID, n, threshold int) ([]KeyShard, error) {
	if threshold > n || threshold < 2 {
		return nil, errors.New("keys: invalid threshold")
	}

	material, err := m.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(material)

	shards := make([]KeyShard, n)
	allShares := make([][]byte, n)

	for i := 0; i < n-1; i++ {
		share := make([]byte, len(material))
		allShares[i] = share
	}

	lastShare := make([]byte, len(material))
	copy(lastShare, material)
	for i := 0; i < n-1; i++ {
		for j := range lastShare {
			lastShare[j] ^= allShares[i][j]
		}
	}
	allShares[n-1] = lastShare

	for i := 0; i < n; i++ {
		shardID, _ := m.crypto.GenerateRandomID()
		shards[i] = KeyShard{
			ID:        shardID,
			KeyID:     id,
			Index:     i + 1,
			Threshold: threshold,
			Total:     n,
			Data:      allShares[i],
			Hash:      m.crypto.Hash(allShares[i]),
		}
	}

	return shards, nil
}

// RecombineKey recombines key from shards
func (m *Manager) RecombineKey(ctx context.Context, shards []KeyShard) ([]byte, error) {
	if len(shards) == 0 {
		return nil, ErrInsufficientShards
	}

	threshold := shards[0].Threshold
	if len(shards) < threshold {
		return nil, ErrInsufficientShards
	}

	for _, shard := range shards {
		if !security.ConstantTimeCompare(shard.Hash, m.crypto.Hash(shard.Data)) {
			return nil, ErrInvalidShard
		}
	}

	keyLen := len(shards[0].Data)
	result := make([]byte, keyLen)
	for _, shard := range shards {
		for i := 0; i < keyLen; i++ {
			result[i] ^= shard.Data[i]
		}
	}

	return result, nil
}

type keyExport struct {
	ID        types.ID      `json:"id"`
	Type      types.KeyType `json:"type"`
	Algorithm string        `json:"algorithm"`
	Material  []byte        `json:"material"`
}

// ExportKey exports a key for backup
func (m *Manager) ExportKey(ctx context.Context, id types.ID, exportKey []byte) ([]byte, error) {
	material, err := m.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(material)

	key, err := m.GetKeyMetadata(ctx, id)
	if err != nil {
		return nil, err
	}

	export := keyExport{ID: key.ID, Type: key.Type, Algorithm: key.Algorithm, Material: material}
	data, _ := json.Marshal(export)
	return m.crypto.Encrypt(exportKey, data, []byte("key_export"))
}

// ImportKey imports a key from backup
func (m *Manager) ImportKey(ctx context.Context, encryptedExport []byte, importKey []byte) (*types.Key, error) {
	exportData, err := m.crypto.Decrypt(importKey, encryptedExport, []byte("key_export"))
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(exportData)

	var export keyExport
	if err := json.Unmarshal(exportData, &export); err != nil {
		return nil, err
	}
	defer security.Zeroize(export.Material)

	encryptedMaterial, err := m.crypto.Encrypt(m.masterKey.Bytes(), export.Material, []byte(export.ID))
	if err != nil {
		return nil, err
	}

	now := types.Now()
	key := &types.Key{
		ID:        export.ID,
		Type:      export.Type,
		Algorithm: export.Algorithm,
		Version:   1,
		CreatedAt: now,
		Status:    types.StatusActive,
		Material:  encryptedMaterial,
	}

	if err := m.keyStore.Set(ctx, string(export.ID), key); err != nil {
		return nil, err
	}

	return key, nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.masterKey != nil {
		m.masterKey.Free()
	}
	return m.crypto.Close()
}

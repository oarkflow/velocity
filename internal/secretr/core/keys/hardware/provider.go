// Package hardware provides hardware-backed key storage abstraction.
package hardware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrNotAvailable     = errors.New("hardware: provider not available")
	ErrKeyNotFound      = errors.New("hardware: key not found")
	ErrOperationFailed  = errors.New("hardware: operation failed")
	ErrUnsupportedAlgo  = errors.New("hardware: unsupported algorithm")
	ErrProviderClosed   = errors.New("hardware: provider is closed")
)

// KeyAlgorithm represents supported key algorithms
type KeyAlgorithm string

const (
	AlgorithmECDSAP256   KeyAlgorithm = "ecdsa-p256"
	AlgorithmECDSAP384   KeyAlgorithm = "ecdsa-p384"
	AlgorithmRSA2048     KeyAlgorithm = "rsa-2048"
	AlgorithmRSA4096     KeyAlgorithm = "rsa-4096"
	AlgorithmEd25519     KeyAlgorithm = "ed25519"
	AlgorithmAES256      KeyAlgorithm = "aes-256"
)

// KeyUsage represents the permitted uses for a key
type KeyUsage uint

const (
	UsageSign    KeyUsage = 1 << iota
	UsageVerify
	UsageEncrypt
	UsageDecrypt
	UsageWrap
	UsageUnwrap
	UsageDerive
)

// KeyHandle represents a reference to a hardware-stored key
type KeyHandle struct {
	ID           types.ID     `json:"id"`
	ProviderType ProviderType `json:"provider_type"`
	KeySlot      uint         `json:"key_slot,omitempty"`
	Algorithm    KeyAlgorithm `json:"algorithm"`
	Usage        KeyUsage     `json:"usage"`
	Label        string       `json:"label,omitempty"`
	CreatedAt    types.Timestamp `json:"created_at"`
	opaque       interface{}  // Provider-specific data
}

// GenerateKeyOptions holds key generation options
type GenerateKeyOptions struct {
	Algorithm KeyAlgorithm
	Usage     KeyUsage
	Label     string
	KeySlot   *uint // Optional specific slot
}

// Provider defines the interface for hardware security modules
type Provider interface {
	// Type returns the provider type
	Type() ProviderType

	// IsAvailable checks if the hardware is available
	IsAvailable() bool

	// Open initializes the hardware connection
	Open() error

	// Close closes the hardware connection
	Close() error

	// GenerateKey generates a key in hardware
	GenerateKey(ctx context.Context, opts GenerateKeyOptions) (*KeyHandle, error)

	// ImportKey imports an existing key into hardware
	ImportKey(ctx context.Context, keyData []byte, opts GenerateKeyOptions) (*KeyHandle, error)

	// GetPublicKey retrieves the public key component
	GetPublicKey(ctx context.Context, handle *KeyHandle) ([]byte, error)

	// Sign signs data using the hardware key
	Sign(ctx context.Context, handle *KeyHandle, data []byte) ([]byte, error)

	// Verify verifies a signature using the hardware key
	Verify(ctx context.Context, handle *KeyHandle, data, signature []byte) error

	// Encrypt encrypts data using the hardware key
	Encrypt(ctx context.Context, handle *KeyHandle, plaintext []byte) ([]byte, error)

	// Decrypt decrypts data using the hardware key
	Decrypt(ctx context.Context, handle *KeyHandle, ciphertext []byte) ([]byte, error)

	// DestroyKey destroys a key in hardware
	DestroyKey(ctx context.Context, handle *KeyHandle) error

	// ListKeys lists all keys in the hardware
	ListKeys(ctx context.Context) ([]*KeyHandle, error)
}

// ProviderType represents the type of hardware provider
type ProviderType string

const (
	ProviderTPM          ProviderType = "tpm"
	ProviderHSM          ProviderType = "hsm"
	ProviderSecureEnclave ProviderType = "secure_enclave"
	ProviderSoftware     ProviderType = "software" // Fallback
)

// Manager manages hardware security providers
type Manager struct {
	mu        sync.RWMutex
	providers map[ProviderType]Provider
	primary   ProviderType
}

// ManagerConfig configures the hardware manager
type ManagerConfig struct {
	PrimaryProvider ProviderType
}

// NewManager creates a new hardware manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		providers: make(map[ProviderType]Provider),
		primary:   cfg.PrimaryProvider,
	}
}

// RegisterProvider registers a hardware provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Type()] = provider
}

// GetProvider returns a specific provider
func (m *Manager) GetProvider(t ProviderType) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[t]
	if !ok {
		return nil, ErrNotAvailable
	}
	return p, nil
}

// GetPrimaryProvider returns the primary provider
func (m *Manager) GetPrimaryProvider() (Provider, error) {
	return m.GetProvider(m.primary)
}

// GetAvailableProvider returns the first available provider
func (m *Manager) GetAvailableProvider() (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Try primary first
	if p, ok := m.providers[m.primary]; ok && p.IsAvailable() {
		return p, nil
	}

	// Fall back to any available
	for _, p := range m.providers {
		if p.IsAvailable() {
			return p, nil
		}
	}

	return nil, ErrNotAvailable
}

// GenerateKey generates a key using the best available provider
func (m *Manager) GenerateKey(ctx context.Context, opts GenerateKeyOptions) (*KeyHandle, error) {
	provider, err := m.GetAvailableProvider()
	if err != nil {
		return nil, err
	}
	return provider.GenerateKey(ctx, opts)
}

// OpenAll opens all registered providers
func (m *Manager) OpenAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.providers {
		if err := p.Open(); err != nil {
			// Log but continue - some providers may not be available
			continue
		}
	}
	return nil
}

// Close closes all providers
func (m *Manager) Close() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.providers {
		p.Close()
	}
	return nil
}

// SoftwareProvider implements Provider as a fallback (in-memory)
type SoftwareProvider struct {
	mu      sync.RWMutex
	keys    map[types.ID]*softwareKey
	open    bool
}

type softwareKey struct {
	handle     *KeyHandle
	privateKey []byte
	publicKey  []byte
}

// NewSoftwareProvider creates a software-based provider
func NewSoftwareProvider() *SoftwareProvider {
	return &SoftwareProvider{
		keys: make(map[types.ID]*softwareKey),
	}
}

func (p *SoftwareProvider) Type() ProviderType {
	return ProviderSoftware
}

func (p *SoftwareProvider) IsAvailable() bool {
	return true // Always available
}

func (p *SoftwareProvider) Open() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = true
	return nil
}

func (p *SoftwareProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = false
	return nil
}

func (p *SoftwareProvider) GenerateKey(ctx context.Context, opts GenerateKeyOptions) (*KeyHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	// Generate a random ID
	id := types.ID(generateRandomID())

	handle := &KeyHandle{
		ID:           id,
		ProviderType: ProviderSoftware,
		Algorithm:    opts.Algorithm,
		Usage:        opts.Usage,
		Label:        opts.Label,
		CreatedAt:    types.Now(),
	}

	// In real implementation, generate actual keys based on algorithm
	// For now, just store placeholder
	p.keys[id] = &softwareKey{
		handle:     handle,
		privateKey: []byte("placeholder-private-key"),
		publicKey:  []byte("placeholder-public-key"),
	}

	return handle, nil
}

func (p *SoftwareProvider) ImportKey(ctx context.Context, keyData []byte, opts GenerateKeyOptions) (*KeyHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	id := types.ID(generateRandomID())

	handle := &KeyHandle{
		ID:           id,
		ProviderType: ProviderSoftware,
		Algorithm:    opts.Algorithm,
		Usage:        opts.Usage,
		Label:        opts.Label,
		CreatedAt:    types.Now(),
	}

	p.keys[id] = &softwareKey{
		handle:     handle,
		privateKey: keyData,
	}

	return handle, nil
}

func (p *SoftwareProvider) GetPublicKey(ctx context.Context, handle *KeyHandle) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	key, ok := p.keys[handle.ID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return key.publicKey, nil
}

func (p *SoftwareProvider) Sign(ctx context.Context, handle *KeyHandle, data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	_, ok := p.keys[handle.ID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Placeholder - real implementation would use actual signing
	return []byte("placeholder-signature"), nil
}

func (p *SoftwareProvider) Verify(ctx context.Context, handle *KeyHandle, data, signature []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return ErrProviderClosed
	}

	_, ok := p.keys[handle.ID]
	if !ok {
		return ErrKeyNotFound
	}

	// Placeholder verification
	return nil
}

func (p *SoftwareProvider) Encrypt(ctx context.Context, handle *KeyHandle, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	_, ok := p.keys[handle.ID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Placeholder encryption
	return append([]byte("encrypted:"), plaintext...), nil
}

func (p *SoftwareProvider) Decrypt(ctx context.Context, handle *KeyHandle, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	_, ok := p.keys[handle.ID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Placeholder decryption
	if len(ciphertext) > 10 {
		return ciphertext[10:], nil
	}
	return ciphertext, nil
}

func (p *SoftwareProvider) DestroyKey(ctx context.Context, handle *KeyHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.open {
		return ErrProviderClosed
	}

	delete(p.keys, handle.ID)
	return nil
}

func (p *SoftwareProvider) ListKeys(ctx context.Context) ([]*KeyHandle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.open {
		return nil, ErrProviderClosed
	}

	var handles []*KeyHandle
	for _, k := range p.keys {
		handles = append(handles, k.handle)
	}
	return handles, nil
}

// TPMProviderConfig configures the TPM provider
type TPMProviderConfig struct {
	DevicePath string // e.g., "/dev/tpm0" or "simulator"
}

// TPMProvider implements Provider for TPM 2.0
type TPMProvider struct {
	mu         sync.RWMutex
	config     TPMProviderConfig
	device     io.ReadWriteCloser
	open       bool
	keys       map[types.ID]*KeyHandle
}

// NewTPMProvider creates a new TPM provider
func NewTPMProvider(cfg TPMProviderConfig) *TPMProvider {
	return &TPMProvider{
		config: cfg,
		keys:   make(map[types.ID]*KeyHandle),
	}
}

func (p *TPMProvider) Type() ProviderType {
	return ProviderTPM
}

func (p *TPMProvider) IsAvailable() bool {
	// In real implementation, check if TPM device exists
	return false // Not implemented yet
}

func (p *TPMProvider) Open() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// In real implementation, open TPM device
	// For now, return not available
	return ErrNotAvailable
}

func (p *TPMProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.device != nil {
		p.device.Close()
		p.device = nil
	}
	p.open = false
	return nil
}

func (p *TPMProvider) GenerateKey(ctx context.Context, opts GenerateKeyOptions) (*KeyHandle, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) ImportKey(ctx context.Context, keyData []byte, opts GenerateKeyOptions) (*KeyHandle, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) GetPublicKey(ctx context.Context, handle *KeyHandle) ([]byte, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) Sign(ctx context.Context, handle *KeyHandle, data []byte) ([]byte, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) Verify(ctx context.Context, handle *KeyHandle, data, signature []byte) error {
	return ErrNotAvailable
}

func (p *TPMProvider) Encrypt(ctx context.Context, handle *KeyHandle, plaintext []byte) ([]byte, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) Decrypt(ctx context.Context, handle *KeyHandle, ciphertext []byte) ([]byte, error) {
	return nil, ErrNotAvailable
}

func (p *TPMProvider) DestroyKey(ctx context.Context, handle *KeyHandle) error {
	return ErrNotAvailable
}

func (p *TPMProvider) ListKeys(ctx context.Context) ([]*KeyHandle, error) {
	return nil, ErrNotAvailable
}

// Helper function to generate random IDs
func generateRandomID() string {
	// Simple placeholder - real implementation would use crypto/rand
	return "hw-" + fmt.Sprintf("%d", types.Now())
}

package velocity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// CryptoMode defines the encryption mode
type CryptoMode string

const (
	// CryptoModeFIPS uses FIPS 140-2 approved algorithms (AES-256-GCM)
	CryptoModeFIPS CryptoMode = "fips"
	// CryptoModeStandard uses high-performance algorithms (ChaCha20-Poly1305)
	CryptoModeStandard CryptoMode = "standard"
)

// FIPSCryptoProvider implements FIPS 140-2 compliant encryption
// Uses AES-256-GCM (NIST SP 800-38D) for authenticated encryption
type FIPSCryptoProvider struct {
	aead       cipher.AEAD
	keyVersion int
	keyID      string
	createdAt  time.Time
}

// NewFIPSCryptoProvider creates a new FIPS-compliant crypto provider
// Key must be exactly 32 bytes (256 bits) for AES-256
func NewFIPSCryptoProvider(key []byte) (*FIPSCryptoProvider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes for AES-256, got %d", len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM (Galois/Counter Mode) for authenticated encryption
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &FIPSCryptoProvider{
		aead:       aead,
		keyVersion: 1,
		keyID:      generateKeyID(),
		createdAt:  time.Now(),
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns nonce and ciphertext separately
func (fcp *FIPSCryptoProvider) Encrypt(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	// Generate random nonce (12 bytes for GCM)
	nonce = make([]byte, fcp.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext = fcp.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (fcp *FIPSCryptoProvider) Decrypt(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != fcp.aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: expected %d, got %d", fcp.aead.NonceSize(), len(nonce))
	}

	plaintext, err := fcp.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// KeyInfo returns key metadata
func (fcp *FIPSCryptoProvider) KeyInfo() KeyVersionInfo {
	return KeyVersionInfo{
		Version:    fcp.keyVersion,
		KeyID:      fcp.keyID,
		CreatedAt:  fcp.createdAt,
		Status:     "active",
		Algorithm:  "AES-256-GCM",
		CryptoMode: string(CryptoModeFIPS),
	}
}

// KeyVersionInfo tracks encryption key metadata
type KeyVersionInfo struct {
	Version       int       `json:"version"`
	KeyID         string    `json:"key_id"`
	CreatedAt     time.Time `json:"created_at"`
	RotatedAt     time.Time `json:"rotated_at,omitempty"`
	RetiredAt     time.Time `json:"retired_at,omitempty"`
	Status        string    `json:"status"` // active, rotating, rotated, retired
	Algorithm     string    `json:"algorithm"`
	CryptoMode    string    `json:"crypto_mode"`
	HSMProviderID string    `json:"hsm_provider_id,omitempty"`
}

// generateKeyID creates a unique key identifier
func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("key-%s", hex.EncodeToString(b))
}

// DeriveKeyPBKDF2 derives a key from password using PBKDF2-HMAC-SHA256
// FIPS 140-2 compliant (NIST SP 800-132)
func DeriveKeyPBKDF2(password, salt []byte, iterations int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) < 16 {
		return nil, errors.New("salt must be at least 16 bytes")
	}
	if iterations < 10000 {
		return nil, errors.New("iterations must be at least 10,000 for PBKDF2")
	}

	// Derive 32-byte key (256 bits) using SHA-256
	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
	return key, nil
}

// DeriveKeyArgon2id derives a key from password using Argon2id
// Recommended for non-FIPS scenarios (RFC 9106)
// Winner of the Password Hashing Competition
func DeriveKeyArgon2id(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) < 16 {
		return nil, errors.New("salt must be at least 16 bytes")
	}

	// OWASP recommended parameters for Argon2id
	// Time: 3 iterations
	// Memory: 64 MB (65536 KB)
	// Threads: 4 parallel threads
	// Output: 32 bytes
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	return key, nil
}

// GenerateSalt creates a cryptographically secure random salt
func GenerateSalt(length int) ([]byte, error) {
	if length < 16 {
		return nil, errors.New("salt length must be at least 16 bytes")
	}

	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// GenerateKey creates a new random 256-bit key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// KeyDerivationConfig holds key derivation parameters
type KeyDerivationConfig struct {
	Method     string `json:"method"`      // pbkdf2, argon2id
	Iterations int    `json:"iterations"`  // For PBKDF2 (min 10,000)
	Memory     int    `json:"memory"`      // For Argon2id (KB)
	Threads    int    `json:"threads"`     // For Argon2id
	SaltLength int    `json:"salt_length"` // Bytes (min 16)
}

// DefaultFIPSKeyDerivation returns FIPS-compliant KDF config
func DefaultFIPSKeyDerivation() KeyDerivationConfig {
	return KeyDerivationConfig{
		Method:     "pbkdf2",
		Iterations: 100000, // OWASP recommendation for PBKDF2
		SaltLength: 32,
	}
}

// DefaultArgon2KeyDerivation returns Argon2id config
func DefaultArgon2KeyDerivation() KeyDerivationConfig {
	return KeyDerivationConfig{
		Method:     "argon2id",
		Memory:     65536, // 64 MB
		Threads:    4,
		SaltLength: 32,
	}
}

// DeriveKey derives a key using the specified configuration
func DeriveKey(password, salt []byte, config KeyDerivationConfig) ([]byte, error) {
	switch config.Method {
	case "pbkdf2":
		return DeriveKeyPBKDF2(password, salt, config.Iterations)
	case "argon2id":
		return DeriveKeyArgon2id(password, salt)
	default:
		return nil, fmt.Errorf("unsupported key derivation method: %s", config.Method)
	}
}

// CryptoConfig defines the cryptography configuration for the database
type CryptoConfig struct {
	Mode              CryptoMode          `json:"mode"`
	KeyDerivation     KeyDerivationConfig `json:"key_derivation"`
	KeyRotationPolicy KeyRotationPolicy   `json:"key_rotation_policy"`
}

// DefaultFIPSConfig returns a FIPS 140-2 compliant configuration
func DefaultFIPSConfig() CryptoConfig {
	return CryptoConfig{
		Mode:          CryptoModeFIPS,
		KeyDerivation: DefaultFIPSKeyDerivation(),
		KeyRotationPolicy: KeyRotationPolicy{
			Enabled:           true,
			RotationInterval:  90 * 24 * time.Hour, // 90 days
			MaxKeyAge:         365 * 24 * time.Hour, // 1 year
			ReencryptionBatch: 1000,
		},
	}
}

// DefaultStandardConfig returns a high-performance configuration
func DefaultStandardConfig() CryptoConfig {
	return CryptoConfig{
		Mode:          CryptoModeStandard,
		KeyDerivation: DefaultArgon2KeyDerivation(),
		KeyRotationPolicy: KeyRotationPolicy{
			Enabled:           true,
			RotationInterval:  180 * 24 * time.Hour, // 180 days
			MaxKeyAge:         365 * 24 * time.Hour,  // 1 year
			ReencryptionBatch: 1000,
		},
	}
}

// ValidateFIPSCompliance checks if the configuration meets FIPS requirements
func ValidateFIPSCompliance(config CryptoConfig) error {
	if config.Mode != CryptoModeFIPS {
		return errors.New("FIPS mode required for FIPS compliance")
	}

	if config.KeyDerivation.Method != "pbkdf2" {
		return errors.New("FIPS requires PBKDF2 for key derivation")
	}

	if config.KeyDerivation.Iterations < 10000 {
		return errors.New("FIPS requires at least 10,000 PBKDF2 iterations")
	}

	if config.KeyDerivation.SaltLength < 16 {
		return errors.New("FIPS requires at least 16-byte salt")
	}

	return nil
}

// SecureZero overwrites sensitive data in memory
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

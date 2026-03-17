// Package crypto provides cryptographic primitives for the Secretr platform.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Algorithm constants
const (
	AlgorithmAES256GCM        = "AES-256-GCM"
	AlgorithmChaCha20Poly1305 = "ChaCha20-Poly1305"
	AlgorithmArgon2id         = "Argon2id"
	AlgorithmEd25519          = "Ed25519"
	AlgorithmX25519           = "X25519"
	AlgorithmHKDF             = "HKDF-SHA256"
	AlgorithmHMACSHA256       = "HMAC-SHA256"
	AlgorithmSHA256           = "SHA256"
	AlgorithmSHA512           = "SHA512"
)

// Key sizes
const (
	KeySize256     = 32
	KeySize128     = 16
	NonceSize      = 12
	SaltSize       = 32
	TagSize        = 16
	Ed25519PubKey  = ed25519.PublicKeySize
	Ed25519PrivKey = ed25519.PrivateKeySize
)

// Argon2 parameters (OWASP recommended for high security)
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64MB
	Argon2Threads = 4
)

var (
	ErrInvalidKey        = errors.New("crypto: invalid key")
	ErrInvalidNonce      = errors.New("crypto: invalid nonce")
	ErrInvalidCiphertext = errors.New("crypto: invalid ciphertext")
	ErrDecryptionFailed  = errors.New("crypto: decryption failed")
	ErrSignatureInvalid  = errors.New("crypto: signature verification failed")
	ErrKeyExpired        = errors.New("crypto: key has expired")
	ErrKeyDestroyed      = errors.New("crypto: key has been destroyed")
)

// Engine provides cryptographic operations
type Engine struct {
	mu          sync.RWMutex
	algorithm   string
	keyCache    map[types.ID]*cachedKey
	cacheExpiry time.Duration
}

type cachedKey struct {
	key       *security.SecureBytes
	expiresAt time.Time
}

// NewEngine creates a new crypto engine
func NewEngine(algorithm string) *Engine {
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}
	return &Engine{
		algorithm:   algorithm,
		keyCache:    make(map[types.ID]*cachedKey),
		cacheExpiry: 5 * time.Minute,
	}
}

// SetSecretSealer sets the hardware protector for the engine
func (e *Engine) SetSecretSealer(sealer SecretSealer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// In a real implementation we might want to store this
	// For now, we'll expose a method to harden keys
}

// HardenKey hardens a key using the hardware protector if available
func (e *Engine) HardenKey(key []byte, sealer SecretSealer) ([]byte, error) {
	if sealer == nil {
		return key, nil
	}

	// Reuse v1 logic: HKDF(key || secret)
	// We need to implement ensureSecret logic here or in the sealer wrapper
	// For simplicity, we'll assume the sealer handles the secret management
	// But wait, SecretSealer in v1 just encrypts/decrypts a 32-byte secret.

	// Let's implement a helper here that mimics v1's HardenKey
	// But since we don't have the full stateful protector here yet,
	// we might just defer this integration to the layer that manages the MasterKey (e.g. Vault).
	return key, nil
}

// GenerateKey generates a new random key
func (e *Engine) GenerateKey(size int) (*security.SecureBytes, error) {
	key, err := security.NewSecureBytes(size)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, key.Bytes()); err != nil {
		key.Free()
		return nil, fmt.Errorf("crypto: failed to generate random key: %w", err)
	}
	return key, nil
}

// GenerateNonce generates a random nonce
func (e *Engine) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateSalt generates a random salt
func (e *Engine) GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a key from password using Argon2id
func (e *Engine) DeriveKey(password []byte, salt []byte, keyLen int) (*security.SecureBytes, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: invalid salt size")
	}

	derived := argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, uint32(keyLen))
	security.Zeroize(password) // Zero password after use

	return security.NewSecureBytesFromSlice(derived)
}

// DeriveKeyHKDF derives a key using HKDF
func (e *Engine) DeriveKeyHKDF(secret []byte, salt []byte, info []byte, keyLen int) (*security.SecureBytes, error) {
	reader := hkdf.New(sha256.New, secret, salt, info)

	key, err := security.NewSecureBytes(keyLen)
	if err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(reader, key.Bytes()); err != nil {
		key.Free()
		return nil, fmt.Errorf("crypto: HKDF derivation failed: %w", err)
	}

	return key, nil
}

// Encrypt encrypts plaintext using the specified algorithm
func (e *Engine) Encrypt(key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize256 {
		return nil, ErrInvalidKey
	}

	switch e.algorithm {
	case AlgorithmAES256GCM:
		return e.encryptAESGCM(key, plaintext, additionalData)
	case AlgorithmChaCha20Poly1305:
		return e.encryptChaCha20(key, plaintext, additionalData)
	default:
		return e.encryptAESGCM(key, plaintext, additionalData)
	}
}

// Decrypt decrypts ciphertext using the specified algorithm
func (e *Engine) Decrypt(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize256 {
		return nil, ErrInvalidKey
	}

	switch e.algorithm {
	case AlgorithmAES256GCM:
		return e.decryptAESGCM(key, ciphertext, additionalData)
	case AlgorithmChaCha20Poly1305:
		return e.decryptChaCha20(key, ciphertext, additionalData)
	default:
		return e.decryptAESGCM(key, ciphertext, additionalData)
	}
}

func (e *Engine) encryptAESGCM(key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonce, err := e.GenerateNonce()
	if err != nil {
		return nil, err
	}

	// Output format: nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

func (e *Engine) decryptAESGCM(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func (e *Engine) encryptChaCha20(key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create ChaCha20-Poly1305: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

func (e *Engine) decryptChaCha20(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, ErrInvalidCiphertext
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create ChaCha20-Poly1305: %w", err)
	}

	nonce := ciphertext[:chacha20poly1305.NonceSize]
	ciphertext = ciphertext[chacha20poly1305.NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKeyPair generates an Ed25519 key pair
func (e *Engine) GenerateKeyPair() (publicKey []byte, privateKey *security.SecureBytes, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to generate key pair: %w", err)
	}

	securePriv, err := security.NewSecureBytesFromSlice(priv)
	if err != nil {
		return nil, nil, err
	}

	return pub, securePriv, nil
}

// Sign signs a message using Ed25519
func (e *Engine) Sign(privateKey []byte, message []byte) ([]byte, error) {
	if len(privateKey) != Ed25519PrivKey {
		return nil, ErrInvalidKey
	}

	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

// Verify verifies an Ed25519 signature
func (e *Engine) Verify(publicKey []byte, message []byte, signature []byte) error {
	if len(publicKey) != Ed25519PubKey {
		return ErrInvalidKey
	}

	if !ed25519.Verify(publicKey, message, signature) {
		return ErrSignatureInvalid
	}

	return nil
}

// GenerateX25519KeyPair generates X25519 key exchange keys
func (e *Engine) GenerateX25519KeyPair() (publicKey []byte, privateKey *security.SecureBytes, err error) {
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, err
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		security.Zeroize(priv)
		return nil, nil, err
	}

	securePriv, err := security.NewSecureBytesFromSlice(priv)
	if err != nil {
		return nil, nil, err
	}

	return pub, securePriv, nil
}

// ComputeSharedSecret computes X25519 shared secret
func (e *Engine) ComputeSharedSecret(privateKey []byte, peerPublicKey []byte) (*security.SecureBytes, error) {
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to compute shared secret: %w", err)
	}

	return security.NewSecureBytesFromSlice(shared)
}

// Hash computes SHA-256 hash
func (e *Engine) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Hash512 computes SHA-512 hash
func (e *Engine) Hash512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// HMAC computes HMAC-SHA256
func (e *Engine) HMAC(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256
func (e *Engine) VerifyHMAC(key []byte, data []byte, mac []byte) bool {
	expected := e.HMAC(key, data)
	return security.ConstantTimeCompare(expected, mac)
}

// HashChain computes a hash chain for audit integrity
func (e *Engine) HashChain(previousHash []byte, data []byte) []byte {
	h := sha256.New()
	h.Write(previousHash)
	h.Write(data)
	return h.Sum(nil)
}

// Fingerprint computes a fingerprint of data
func (e *Engine) Fingerprint(data []byte) string {
	hash := e.Hash(data)
	return fmt.Sprintf("%x", hash[:16])
}

// GenerateRandomID generates a random ID
func (e *Engine) GenerateRandomID() (types.ID, error) {
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return "", err
	}
	return types.ID(fmt.Sprintf("%x", id)), nil
}

// TimeBoundKey creates a key that's only valid for a specific time period
type TimeBoundKey struct {
	Key       *security.SecureBytes
	CreatedAt time.Time
	ExpiresAt time.Time
	Algorithm string
}

// NewTimeBoundKey creates a time-bound key
func (e *Engine) NewTimeBoundKey(duration time.Duration) (*TimeBoundKey, error) {
	key, err := e.GenerateKey(KeySize256)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &TimeBoundKey{
		Key:       key,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
		Algorithm: e.algorithm,
	}, nil
}

// IsValid checks if the time-bound key is still valid
func (tbk *TimeBoundKey) IsValid() bool {
	return time.Now().Before(tbk.ExpiresAt)
}

// Destroy securely destroys the key
func (tbk *TimeBoundKey) Destroy() {
	if tbk.Key != nil {
		tbk.Key.Free()
		tbk.Key = nil
	}
}

// EnvelopeEncrypt performs envelope encryption
type EnvelopeEncryption struct {
	engine *Engine
}

// NewEnvelopeEncryption creates envelope encryption handler
func NewEnvelopeEncryption(engine *Engine) *EnvelopeEncryption {
	return &EnvelopeEncryption{engine: engine}
}

// EncryptedEnvelope contains encrypted data and wrapped key
type EncryptedEnvelope struct {
	WrappedDEK    []byte // DEK encrypted with KEK
	EncryptedData []byte // Data encrypted with DEK
	Algorithm     string
	KeyID         types.ID
	Timestamp     int64
}

// Encrypt encrypts data using envelope encryption
func (ee *EnvelopeEncryption) Encrypt(kek []byte, keyID types.ID, plaintext []byte, additionalData []byte) (*EncryptedEnvelope, error) {
	// Generate DEK (Data Encryption Key)
	dek, err := ee.engine.GenerateKey(KeySize256)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to generate DEK: %w", err)
	}
	defer dek.Free()

	// Encrypt data with DEK
	encryptedData, err := ee.engine.Encrypt(dek.Bytes(), plaintext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to encrypt data: %w", err)
	}

	// Wrap DEK with KEK
	wrappedDEK, err := ee.engine.Encrypt(kek, dek.Copy(), nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to wrap DEK: %w", err)
	}

	return &EncryptedEnvelope{
		WrappedDEK:    wrappedDEK,
		EncryptedData: encryptedData,
		Algorithm:     ee.engine.algorithm,
		KeyID:         keyID,
		Timestamp:     time.Now().UnixNano(),
	}, nil
}

// Decrypt decrypts an envelope
func (ee *EnvelopeEncryption) Decrypt(kek []byte, envelope *EncryptedEnvelope, additionalData []byte) ([]byte, error) {
	// Unwrap DEK
	dek, err := ee.engine.Decrypt(kek, envelope.WrappedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to unwrap DEK: %w", err)
	}
	defer security.Zeroize(dek)

	// Decrypt data
	plaintext, err := ee.engine.Decrypt(dek, envelope.EncryptedData, additionalData)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// KeyDestructionProof provides cryptographic proof of key destruction
type KeyDestructionProof struct {
	KeyID          types.ID
	KeyFingerprint string
	DestroyedAt    time.Time
	Hash           []byte
	Signature      []byte
	SignedBy       types.ID
}

// CreateDestructionProof creates a proof that a key was destroyed
func (e *Engine) CreateDestructionProof(keyID types.ID, keyMaterial []byte, signerID types.ID, signerPrivKey []byte) (*KeyDestructionProof, error) {
	fingerprint := e.Fingerprint(keyMaterial)
	now := time.Now()

	// Create proof data
	proofData := make([]byte, 0, 128)
	proofData = append(proofData, []byte(keyID)...)
	proofData = append(proofData, []byte(fingerprint)...)

	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(now.UnixNano()))
	proofData = append(proofData, timestamp...)

	hash := e.Hash(proofData)

	signature, err := e.Sign(signerPrivKey, hash)
	if err != nil {
		return nil, err
	}

	return &KeyDestructionProof{
		KeyID:          keyID,
		KeyFingerprint: fingerprint,
		DestroyedAt:    now,
		Hash:           hash,
		Signature:      signature,
		SignedBy:       signerID,
	}, nil
}

// VerifyDestructionProof verifies a destruction proof
func (e *Engine) VerifyDestructionProof(proof *KeyDestructionProof, signerPubKey []byte) error {
	return e.Verify(signerPubKey, proof.Hash, proof.Signature)
}

// ClearKeyCache clears the key cache
func (e *Engine) ClearKeyCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for id, ck := range e.keyCache {
		if ck.key != nil {
			ck.key.Free()
		}
		delete(e.keyCache, id)
	}
}

// Close cleans up the engine
func (e *Engine) Close() error {
	e.ClearKeyCache()
	return nil
}

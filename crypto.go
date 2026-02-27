package velocity

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	masterKeyFilename = "master.key"
	keyMarkerFilename = "key.marker"
	// Known plaintext for key verification
	keyMarkerPlaintext = "velocity-key-verification-marker-v1"
)

// CryptoProvider wraps an AEAD cipher for encrypting values at rest.
type CryptoProvider struct {
	aead      cipher.AEAD
	masterKey []byte
}

func newCryptoProvider(key []byte) (*CryptoProvider, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid encryption key length: expected %d bytes", chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &CryptoProvider{
		aead:      aead,
		masterKey: key,
	}, nil
}

func (cp *CryptoProvider) Encrypt(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = cp.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func (cp *CryptoProvider) Decrypt(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	return cp.aead.Open(nil, nonce, ciphertext, aad)
}

func buildEntryAAD(key []byte, timestamp uint64, expiresAt uint64, deleted bool) []byte {
	var (
		aad        = make([]byte, 0, len(key)+21)
		tmp32      [4]byte
		tmp64      [8]byte
		deleteByte byte
	)
	binary.LittleEndian.PutUint32(tmp32[:], uint32(len(key)))
	aad = append(aad, tmp32[:]...)
	aad = append(aad, key...)
	binary.LittleEndian.PutUint64(tmp64[:], timestamp)
	aad = append(aad, tmp64[:]...)
	binary.LittleEndian.PutUint64(tmp64[:], expiresAt)
	aad = append(aad, tmp64[:]...)
	if deleted {
		deleteByte = 1
	}
	aad = append(aad, deleteByte)
	return aad
}

func ensureMasterKey(dbPath string, explicit []byte) ([]byte, error) {
	if len(explicit) > 0 {
		if len(explicit) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("invalid explicit key length: expected %d bytes", chacha20poly1305.KeySize)
		}
		out := make([]byte, chacha20poly1305.KeySize)
		copy(out, explicit)
		return out, nil
	}

	if envKey, err := loadKeyFromEnv(); err != nil {
		return nil, err
	} else if envKey != nil {
		return envKey, nil
	}

	keyPath := filepath.Join(dbPath, masterKeyFilename)
	data, err := os.ReadFile(keyPath)
	if err == nil {
		key, err := ParseKeyString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("invalid master key file: %w", err)
		}
		return key, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	fresh := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(fresh)
	if err := os.WriteFile(keyPath, []byte(encoded), 0o600); err != nil {
		return nil, err
	}

	return fresh, nil
}

// ensureMasterKeyWithManager uses MasterKeyManager for flexible key management
func ensureMasterKeyWithManager(manager *MasterKeyManager, explicit []byte) ([]byte, error) {
	return manager.GetMasterKey(explicit)
}

func loadKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("VELOCITY_MASTER_KEY"))
	if raw == "" {
		return nil, nil
	}
	key, err := ParseKeyString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid VELOCITY_MASTER_KEY: %w", err)
	}
	return key, nil
}

func ParseKeyString(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty key value")
	}

	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == chacha20poly1305.KeySize {
		return decoded, nil
	}

	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == chacha20poly1305.KeySize {
		return decoded, nil
	}

	if len(value) == chacha20poly1305.KeySize {
		return []byte(value), nil
	}

	return nil, fmt.Errorf("expected 32-byte key (raw/base64/hex), got %d bytes", len(value))
}

func (cp *CryptoProvider) DeriveObjectKey(objectID string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}

	// Use HKDF to derive a unique 32-byte key for the object
	// The underlying AEAD's key is used as the PRK (pseudo-random key)
	// and the objectID as info.
	hash := sha256.New
	kdf := hkdf.New(hash, cp.aeadKey(), salt, []byte(objectID))

	derived := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return derived, nil
}

// AEAD keys are not exposed by the interface, so we need a way to get it
// or store it in the provider. Let's update the provider.
func (cp *CryptoProvider) aeadKey() []byte {
	// Refactor: We need the original key for HKDF
	return cp.masterKey
}

// EncryptStream encrypts data in chunks for streaming
func (cp *CryptoProvider) EncryptStream(plaintext []byte, aad []byte) ([]byte, error) {
	nonce, ciphertext, err := cp.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Combine nonce and ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptStream decrypts data that was encrypted with EncryptStream
func (cp *CryptoProvider) DecryptStream(data []byte, aad []byte) ([]byte, error) {
	if len(data) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid encrypted data: too short")
	}

	nonce := data[:chacha20poly1305.NonceSizeX]
	ciphertext := data[chacha20poly1305.NonceSizeX:]

	return cp.Decrypt(nonce, ciphertext, aad)
}

const ChunkSize = 64 * 1024 // 64KB chunks

type EncryptReader struct {
	cp     *CryptoProvider
	r      io.Reader
	aad    []byte
	buf    []byte
	chunk  []byte
	err    error
	eof    bool
	header bool
	nonce  []byte
}

func (cp *CryptoProvider) NewEncryptReader(r io.Reader, aad []byte) *EncryptReader {
	return &EncryptReader{
		cp:    cp,
		r:     r,
		aad:   aad,
		buf:   make([]byte, 0, ChunkSize+chacha20poly1305.Overhead),
		chunk: make([]byte, ChunkSize),
	}
}

func (er *EncryptReader) Read(p []byte) (n int, err error) {
	if er.err != nil {
		return 0, er.err
	}

	if len(er.buf) == 0 {
		if er.eof {
			return 0, io.EOF
		}

		// Read next chunk
		nr, rerr := io.ReadFull(er.r, er.chunk)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			er.err = rerr
			return 0, rerr
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			er.eof = true
		}

		if nr > 0 {
			nonce, ciphertext, cerr := er.cp.Encrypt(er.chunk[:nr], er.aad)
			if cerr != nil {
				er.err = cerr
				return 0, cerr
			}
			// For simplicity in this implementation, we prepend the nonce to every chunk
			// In a more advanced version, we'd use a single nonce and increment a counter
			er.buf = append(er.buf, nonce...)
			er.buf = append(er.buf, ciphertext...)
		} else if er.eof {
			return 0, io.EOF
		}
	}

	n = copy(p, er.buf)
	er.buf = er.buf[n:]
	return n, nil
}

type DecryptReader struct {
	cp    *CryptoProvider
	r     io.Reader
	aad   []byte
	buf   []byte
	chunk []byte // Full chunk: NonceSizeX + ChunkSize + Overhead
	err   error
	eof   bool
}

func (cp *CryptoProvider) NewDecryptReader(r io.Reader, aad []byte) *DecryptReader {
	return &DecryptReader{
		cp:    cp,
		r:     r,
		aad:   aad,
		buf:   make([]byte, 0, ChunkSize),
		chunk: make([]byte, chacha20poly1305.NonceSizeX+ChunkSize+chacha20poly1305.Overhead),
	}
}

func (dr *DecryptReader) Read(p []byte) (n int, err error) {
	if dr.err != nil {
		return 0, dr.err
	}

	if len(dr.buf) == 0 {
		if dr.eof {
			return 0, io.EOF
		}

		// Read fixed-size encrypted chunks.
		nr, rerr := io.ReadFull(dr.r, dr.chunk)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			dr.err = rerr
			return 0, rerr
		}

		if nr < chacha20poly1305.NonceSizeX+1 {
			dr.eof = true
			return 0, io.EOF
		}

		nonce := dr.chunk[:chacha20poly1305.NonceSizeX]
		ciphertext := dr.chunk[chacha20poly1305.NonceSizeX:nr]

		plaintext, derr := dr.cp.Decrypt(nonce, ciphertext, dr.aad)
		if derr != nil {
			dr.err = derr
			return 0, derr
		}

		dr.buf = plaintext
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			dr.eof = true
		}
	}

	n = copy(p, dr.buf)
	dr.buf = dr.buf[n:]
	return n, nil
}

// KeyVerificationError indicates the provided key doesn't match the stored key marker
type KeyVerificationError struct {
	Message string
}

func (e *KeyVerificationError) Error() string {
	return e.Message
}

// createKeyMarker creates a verification marker for the given key
// This allows us to verify on restart that the user provided the correct key
func createKeyMarker(dbPath string, key []byte) error {
	markerPath := filepath.Join(dbPath, keyMarkerFilename)

	// Create crypto provider with the key
	cp, err := newCryptoProvider(key)
	if err != nil {
		return err
	}

	// Create a hash of the key as additional verification
	keyHash := sha256.Sum256(key)

	// Encrypt the known plaintext with the key
	nonce, ciphertext, err := cp.Encrypt([]byte(keyMarkerPlaintext), keyHash[:])
	if err != nil {
		return err
	}

	// Store: keyHash (32 bytes) + nonce (24 bytes) + ciphertext
	markerData := make([]byte, 0, 32+len(nonce)+len(ciphertext))
	markerData = append(markerData, keyHash[:]...)
	markerData = append(markerData, nonce...)
	markerData = append(markerData, ciphertext...)

	// Write marker file
	encoded := base64.StdEncoding.EncodeToString(markerData)
	return os.WriteFile(markerPath, []byte(encoded), 0600)
}

// verifyKeyMarker checks if the provided key matches the stored key marker
// Returns nil if verification passes, KeyVerificationError if key doesn't match
func verifyKeyMarker(dbPath string, key []byte) error {
	markerPath := filepath.Join(dbPath, keyMarkerFilename)

	data, err := os.ReadFile(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No marker exists, this is the first time - create it
			return createKeyMarker(dbPath, key)
		}
		return err
	}

	// Decode marker data
	markerData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("corrupted key marker file: %w", err)
	}

	if len(markerData) < 32+chacha20poly1305.NonceSizeX+1 {
		return fmt.Errorf("corrupted key marker file: too short")
	}

	// Extract components
	storedKeyHash := markerData[:32]
	nonce := markerData[32 : 32+chacha20poly1305.NonceSizeX]
	ciphertext := markerData[32+chacha20poly1305.NonceSizeX:]

	// First quick check: verify key hash matches
	keyHash := sha256.Sum256(key)
	if !equalBytes(keyHash[:], storedKeyHash) {
		return &KeyVerificationError{
			Message: "master key verification failed: the provided key does not match the key used to create this database. Please provide the correct master key.",
		}
	}

	// Create crypto provider and try to decrypt
	cp, err := newCryptoProvider(key)
	if err != nil {
		return err
	}

	plaintext, err := cp.Decrypt(nonce, ciphertext, keyHash[:])
	if err != nil {
		return &KeyVerificationError{
			Message: "master key verification failed: decryption error. The provided key does not match the key used to create this database.",
		}
	}

	// Verify plaintext matches
	if string(plaintext) != keyMarkerPlaintext {
		return &KeyVerificationError{
			Message: "master key verification failed: marker mismatch. The provided key does not match the key used to create this database.",
		}
	}

	return nil
}

// hasKeyMarker checks if a key marker file exists
func hasKeyMarker(dbPath string) bool {
	markerPath := filepath.Join(dbPath, keyMarkerFilename)
	_, err := os.Stat(markerPath)
	return err == nil
}

// equalBytes compares two byte slices in constant time (for security)
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

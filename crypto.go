package velocity

import (
	"crypto/cipher"
	"crypto/rand"
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
)

const (
	masterKeyFilename = "master.key"
)

// CryptoProvider wraps an AEAD cipher for encrypting values at rest.
type CryptoProvider struct {
	aead cipher.AEAD
}

func newCryptoProvider(key []byte) (*CryptoProvider, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid encryption key length: expected %d bytes", chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &CryptoProvider{aead: aead}, nil
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

func buildEntryAAD(key []byte, timestamp uint64, deleted bool) []byte {
	var (
		aad        = make([]byte, 0, len(key)+13)
		tmp32      [4]byte
		tmp64      [8]byte
		deleteByte byte
	)
	binary.LittleEndian.PutUint32(tmp32[:], uint32(len(key)))
	aad = append(aad, tmp32[:]...)
	aad = append(aad, key...)
	binary.LittleEndian.PutUint64(tmp64[:], timestamp)
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
		key, err := parseKeyString(strings.TrimSpace(string(data)))
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

func loadKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("VELOCITY_MASTER_KEY"))
	if raw == "" {
		return nil, nil
	}
	key, err := parseKeyString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid VELOCITY_MASTER_KEY: %w", err)
	}
	return key, nil
}

func parseKeyString(value string) ([]byte, error) {
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

// Package cryptofips implements a FIPS-140-2-style Velocity v2
// CryptoProvider: AES-256-GCM via crypto/aes + crypto/cipher, with a
// PBKDF2-based key-derivation validator, ported from v1's crypto_fips.go.
// It registers under the same fixed service name "crypto" as
// plugins/crypto-xchacha — only one of the two is enabled per deployment.
//
// Same policy as crypto-xchacha: setting config "enabled": false makes
// Init fail loudly instead of silently disabling encryption.
package cryptofips

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "crypto-fips"

// KeyDerivation mirrors v1's KeyDerivationConfig for the PBKDF2 path only
// (Argon2id is intentionally not FIPS-eligible and left to crypto-xchacha
// callers that want it).
type KeyDerivation struct {
	Iterations int
	SaltLength int
}

// ValidateFIPSCompliance mirrors v1's crypto_fips.go ValidateFIPSCompliance:
// PBKDF2 iterations must be >= 10000 and salt length >= 16 bytes.
func ValidateFIPSCompliance(kd KeyDerivation) error {
	if kd.Iterations < 10000 {
		return errors.New("FIPS requires at least 10,000 PBKDF2 iterations")
	}
	if kd.SaltLength < 16 {
		return errors.New("FIPS requires at least 16-byte salt")
	}
	return nil
}

// DeriveKeyPBKDF2 mirrors v1's DeriveKeyPBKDF2.
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
	return pbkdf2Key(password, salt, iterations), nil
}

type Plugin struct {
	mu        sync.RWMutex
	aead      cipher.AEAD
	masterKey []byte
	log       api.Logger
	health    api.Health
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string           { return pluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	cfg := k.Config().Scoped(pluginName)
	p.log = k.Logger()

	if !cfg.Bool("enabled", true) {
		return fmt.Errorf("%s: refusing to load with enabled=false — remove this plugin from the manifest instead of disabling it in place", pluginName)
	}

	var key []byte
	if keyStr := cfg.String("key", ""); keyStr != "" {
		parsed, err := parseKeyString(keyStr)
		if err != nil {
			return fmt.Errorf("%s: invalid configured key: %w", pluginName, err)
		}
		key = parsed
	} else if password := cfg.String("password", ""); password != "" {
		salt := []byte(cfg.String("salt", ""))
		iterations := cfg.Int("pbkdf2_iterations", 100000)
		if len(salt) < 16 {
			return fmt.Errorf("%s: config.salt must be set and at least 16 bytes when deriving from config.password", pluginName)
		}
		if err := ValidateFIPSCompliance(KeyDerivation{Iterations: iterations, SaltLength: len(salt)}); err != nil {
			return fmt.Errorf("%s: %w", pluginName, err)
		}
		key = pbkdf2Key([]byte(password), salt, iterations)
	} else {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return fmt.Errorf("%s: generating ephemeral key: %w", pluginName, err)
		}
		p.log.Warn(pluginName + ": no key/password configured — generated a random ephemeral master key for this process only. Set config.key or config.password+salt for a real deployment.")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%s: %w", pluginName, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("%s: %w", pluginName, err)
	}
	p.aead = gcm
	p.masterKey = key

	if err := k.Registry().Provide("crypto", &providerAdapter{p: p}); err != nil {
		return err
	}
	p.health = api.Health{Status: "ok"}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }

func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.masterKey {
		p.masterKey[i] = 0
	}
	return nil
}

func (p *Plugin) Health() api.Health { return p.health }

var _ api.Plugin = (*Plugin)(nil)

type providerAdapter struct{ p *Plugin }

func (a *providerAdapter) Name() string { return "aes256gcm-fips" }

func (a *providerAdapter) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	return a.p.encrypt(plaintext, aad)
}

func (a *providerAdapter) Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	return a.p.decrypt(ciphertext, aad)
}

func (a *providerAdapter) EncryptStream(w io.Writer) (io.WriteCloser, error) {
	return &chunkWriter{p: a.p, w: w, buf: make([]byte, 0, 64*1024)}, nil
}

func (a *providerAdapter) DecryptStream(r io.Reader) (io.Reader, error) {
	return &chunkReader{p: a.p, r: r}, nil
}

var _ api.CryptoProvider = (*providerAdapter)(nil)

func (p *Plugin) encrypt(plaintext, aad []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%s: %w", pluginName, err)
	}
	ciphertext := p.aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func (p *Plugin) decrypt(data, aad []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	nonceSize := p.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("%s: ciphertext too short", pluginName)
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%s: decryption failed: %w", pluginName, err)
	}
	return plaintext, nil
}

// --- streaming: length-prefixed sealed chunks (same wire shape as
// crypto-xchacha for consistency, independently implemented here since
// nonce sizes differ: 12 bytes GCM vs 24 bytes XChaCha) ---

type chunkWriter struct {
	p   *Plugin
	w   io.Writer
	buf []byte
}

func (c *chunkWriter) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		space := cap(c.buf) - len(c.buf)
		n := len(b)
		if n > space {
			n = space
		}
		c.buf = append(c.buf, b[:n]...)
		b = b[n:]
		total += n
		if len(c.buf) == cap(c.buf) {
			if err := c.flush(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (c *chunkWriter) flush() error {
	if len(c.buf) == 0 {
		return nil
	}
	sealed, err := c.p.encrypt(c.buf, nil)
	if err != nil {
		return err
	}
	var lp [4]byte
	putUint32(lp[:], uint32(len(sealed)))
	if _, err := c.w.Write(lp[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(sealed); err != nil {
		return err
	}
	c.buf = c.buf[:0]
	return nil
}

func (c *chunkWriter) Close() error { return c.flush() }

type chunkReader struct {
	p    *Plugin
	r    io.Reader
	buf  []byte
	err  error
	head [4]byte
}

func (c *chunkReader) Read(out []byte) (int, error) {
	if c.err != nil && len(c.buf) == 0 {
		return 0, c.err
	}
	if len(c.buf) == 0 {
		if _, err := io.ReadFull(c.r, c.head[:]); err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			c.err = err
			return 0, err
		}
		n := getUint32(c.head[:])
		sealed := make([]byte, n)
		if _, err := io.ReadFull(c.r, sealed); err != nil {
			c.err = err
			return 0, err
		}
		plain, err := c.p.decrypt(sealed, nil)
		if err != nil {
			c.err = err
			return 0, err
		}
		c.buf = plain
	}
	n := copy(out, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func getUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func pbkdf2Key(password, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

func parseKeyString(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty key value")
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(value) == 32 {
		return []byte(value), nil
	}
	return nil, fmt.Errorf("expected 32-byte key (raw/base64/hex), got %d bytes", len(value))
}

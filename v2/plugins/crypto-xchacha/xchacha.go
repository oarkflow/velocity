// Package cryptoxchacha implements the default Velocity v2 CryptoProvider:
// XChaCha20-Poly1305 AEAD with HKDF-derived per-call keys, ported from v1's
// crypto.go. It registers under the fixed service name "crypto".
//
// Unlike v1's newNoopCryptoProvider (an insecure passthrough used only for
// benchmarks), this plugin never silently disables encryption. If a
// deployment wants no encryption at all, the fix is to leave this plugin
// (and crypto-fips) out of the manifest entirely — not to flip a flag
// inside it. Setting config "enabled": false causes Init to fail loudly
// instead of masking that decision.
package cryptoxchacha

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "crypto-xchacha"

// ChunkSize is the streaming chunk size, matching v1's crypto.go.
const ChunkSize = 64 * 1024

type aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}

// Plugin implements api.Plugin. It does NOT implement api.CryptoProvider
// directly (Plugin.Name and CryptoProvider.Name would collide with
// different meanings); see providerAdapter below, which is what actually
// gets registered under the "crypto" service name.
type Plugin struct {
	mu        sync.RWMutex
	aead      aead
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
		return fmt.Errorf("%s: refusing to load with enabled=false — remove this plugin from the manifest instead of disabling it in place, so \"no encryption\" is always an explicit deployment choice, not a masked default", pluginName)
	}

	keyStr := cfg.String("key", "")
	var key []byte
	if keyStr != "" {
		parsed, err := ParseKeyString(keyStr)
		if err != nil {
			return fmt.Errorf("%s: invalid configured key: %w", pluginName, err)
		}
		key = parsed
	} else {
		key = make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return fmt.Errorf("%s: generating ephemeral key: %w", pluginName, err)
		}
		p.log.Warn(pluginName + ": no \"key\" configured — generated a random ephemeral master key for this process only; data encrypted this run is unrecoverable after restart. Set config.key for a real deployment.")
	}

	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("%s: %w", pluginName, err)
	}
	p.aead = a
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

// providerAdapter is the concrete api.CryptoProvider registered under the
// "crypto" service name. Kept distinct from Plugin so Plugin.Name()
// (plugin identity) and CryptoProvider.Name() (algorithm identity) never
// need to be the same method.
type providerAdapter struct{ p *Plugin }

func (a *providerAdapter) Name() string { return "xchacha20poly1305" }

func (a *providerAdapter) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	return a.p.encrypt(plaintext, aad)
}

func (a *providerAdapter) Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	return a.p.decrypt(ciphertext, aad)
}

func (a *providerAdapter) EncryptStream(w io.Writer) (io.WriteCloser, error) {
	return a.p.newEncryptWriteCloser(w), nil
}

func (a *providerAdapter) DecryptStream(r io.Reader) (io.Reader, error) {
	return a.p.newDecryptReader(r), nil
}

var _ api.CryptoProvider = (*providerAdapter)(nil)

func (p *Plugin) encrypt(plaintext, aad []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
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
	return p.aead.Open(nil, nonce, ciphertext, aad)
}

// DeriveObjectKey derives a per-object key via HKDF, matching v1's
// crypto.go DeriveObjectKey. Exposed for callers (e.g. the object/secret
// plugins) that want a unique key per item rather than sharing the master
// AEAD directly. Not part of api.CryptoProvider — accessed via a type
// assertion to *Plugin for callers that specifically need it.
func (p *Plugin) DeriveObjectKey(objectID string, salt []byte) ([]byte, error) {
	p.mu.RLock()
	key := p.masterKey
	p.mu.RUnlock()

	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}
	kdf := hkdf.New(sha256.New, key, salt, []byte(objectID))
	derived := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("%s: key derivation failed: %w", pluginName, err)
	}
	return derived, nil
}

// --- streaming: length-prefixed sealed chunks ---

type encryptWriteCloser struct {
	p   *Plugin
	w   io.Writer
	buf []byte
}

func (p *Plugin) newEncryptWriteCloser(w io.Writer) io.WriteCloser {
	return &encryptWriteCloser{p: p, w: w, buf: make([]byte, 0, ChunkSize)}
}

func (e *encryptWriteCloser) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		space := cap(e.buf) - len(e.buf)
		n := len(b)
		if n > space {
			n = space
		}
		e.buf = append(e.buf, b[:n]...)
		b = b[n:]
		total += n
		if len(e.buf) == cap(e.buf) {
			if err := e.flushChunk(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (e *encryptWriteCloser) flushChunk() error {
	if len(e.buf) == 0 {
		return nil
	}
	sealed, err := e.p.encrypt(e.buf, nil)
	if err != nil {
		return err
	}
	var lenPrefix [4]byte
	putUint32(lenPrefix[:], uint32(len(sealed)))
	if _, err := e.w.Write(lenPrefix[:]); err != nil {
		return err
	}
	if _, err := e.w.Write(sealed); err != nil {
		return err
	}
	e.buf = e.buf[:0]
	return nil
}

func (e *encryptWriteCloser) Close() error {
	return e.flushChunk()
}

type decryptReader struct {
	p    *Plugin
	r    io.Reader
	buf  []byte
	err  error
	head [4]byte
}

func (p *Plugin) newDecryptReader(r io.Reader) io.Reader {
	return &decryptReader{p: p, r: r}
}

func (d *decryptReader) Read(out []byte) (int, error) {
	if d.err != nil && len(d.buf) == 0 {
		return 0, d.err
	}
	if len(d.buf) == 0 {
		if _, err := io.ReadFull(d.r, d.head[:]); err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			d.err = err
			return 0, err
		}
		n := getUint32(d.head[:])
		sealed := make([]byte, n)
		if _, err := io.ReadFull(d.r, sealed); err != nil {
			d.err = err
			return 0, err
		}
		plain, err := d.p.decrypt(sealed, nil)
		if err != nil {
			d.err = err
			return 0, err
		}
		d.buf = plain
	}
	n := copy(out, d.buf)
	d.buf = d.buf[n:]
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

// ParseKeyString accepts a raw/base64/hex-encoded 32-byte key, matching
// v1's crypto.go ParseKeyString.
func ParseKeyString(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("empty key value")
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
	return nil, fmt.Errorf("expected %d-byte key (raw/base64/hex), got %d bytes", chacha20poly1305.KeySize, len(value))
}

package api

import (
	"context"
	"io"
)

// CryptoProvider is the pluggable encryption boundary used by Object,
// Secret, and Backup paths. Reference implementations:
//   - plugins/crypto-xchacha: XChaCha20-Poly1305 AEAD, ported from v1's
//     crypto.go. Default, fastest, not FIPS-certified.
//   - plugins/crypto-fips: AES-256-GCM + PBKDF2, ported from v1's
//     crypto_fips.go, enforcing FIPS-style iteration/salt minimums.
//
// A plugin that needs encryption looks up "crypto" from the registry and
// never hardcodes an algorithm — swapping providers is a manifest change,
// not a code change.
type CryptoProvider interface {
	Name() string
	Encrypt(ctx context.Context, plaintext []byte, aad []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte, aad []byte) (plaintext []byte, err error)
	// EncryptStream/DecryptStream support large payloads (object bodies)
	// without buffering the whole thing in memory.
	EncryptStream(w io.Writer) (io.WriteCloser, error)
	DecryptStream(r io.Reader) (io.Reader, error)
}

// KeyProvider supplies and rotates the master key(s) a CryptoProvider
// derives per-object keys from. plugins/secret's Shamir-backed master key
// manager (ported from v1's master_key_manager.go) implements this.
type KeyProvider interface {
	MasterKey(ctx context.Context) ([]byte, error)
	RotateMasterKey(ctx context.Context) error
}

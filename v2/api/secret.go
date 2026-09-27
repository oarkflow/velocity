package api

import (
	"context"
	"time"
)

// SecretVersion is one sealed version of a secret. Value is already
// sealed (encrypted) by whatever CryptoProvider the secret plugin was
// wired to — SecretService never returns or stores plaintext at rest.
type SecretVersion struct {
	Version   int
	Value     []byte
	CreatedAt time.Time
}

// SecretService is the secrets-management surface plugins/secret exposes,
// distinct from KVService: values are versioned and sealed via a
// CryptoProvider looked up from the registry, never stored as plaintext.
// Publishes TopicSecretSet / TopicSecretRotate / TopicSecretAccess so
// compliance/audit plugins can observe secret lifecycle events.
type SecretService interface {
	// Set creates a new version of name and returns its version number.
	Set(ctx context.Context, name string, value []byte) (version int, err error)
	// Get returns the value for name at version, or the latest if
	// version == 0.
	Get(ctx context.Context, name string, version int) ([]byte, error)
	Versions(ctx context.Context, name string) ([]SecretVersion, error)
	Delete(ctx context.Context, name string) error
	// Rotate re-encrypts the latest version under the current master key
	// (e.g. after a key rotation) without changing the secret's value.
	Rotate(ctx context.Context, name string) error
}

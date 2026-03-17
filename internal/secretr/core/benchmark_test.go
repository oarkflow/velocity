package core

import (
	"context"
	"os"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type mockKeyManager struct{}

func (m *mockKeyManager) GetKey(ctx context.Context, id types.ID) ([]byte, error) {
	return make([]byte, 32), nil
}
func (m *mockKeyManager) GetCurrentKeyID(ctx context.Context) (types.ID, error) {
	return "master-key", nil
}

func BenchmarkSecretRetrieval(b *testing.B) {
	ctx := context.Background()
	path, _ := os.MkdirTemp("", "bench-secret-*")
	defer os.RemoveAll(path)

	store, _ := storage.NewStore(storage.Config{Path: path, EncryptionKey: make([]byte, 32)})

	vault := secrets.NewVault(secrets.VaultConfig{
		Store:      store,
		KeyManager: &mockKeyManager{},
	})

	identityID := types.ID("user-1")
	secretName := "bench-secret"
	secretValue := "super-secure-data-value-that-is-somewhat-long-to-simulate-real-world-payloads"

	_, err := vault.Create(ctx, secrets.CreateSecretOptions{
		Name:      secretName,
		Value:     []byte(secretValue),
		CreatorID: identityID,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vault.Get(ctx, secretName, identityID, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuditLogging(b *testing.B) {
	ctx := context.Background()
	path, _ := os.MkdirTemp("", "bench-audit-*")
	defer os.RemoveAll(path)

	store, _ := storage.NewStore(storage.Config{Path: path, EncryptionKey: make([]byte, 32)})

	engine := audit.NewEngine(audit.EngineConfig{
		Store: store,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := engine.Log(ctx, audit.AuditEventInput{
			Type:    "benchmark",
			Action:  "log-event",
			ActorID: "bench-actor",
			Success: true,
			Details: types.Metadata{"iter": float64(i)},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoEncryption(b *testing.B) {
	engine := crypto.NewEngine("")
	key := make([]byte, 32)
	data := []byte("some data to encrypt for benchmarking purposes")
	aad := []byte("aad")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Encrypt(key, data, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

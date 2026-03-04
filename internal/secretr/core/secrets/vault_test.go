package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type mockKeyProvider struct {
	key   []byte
	keyID types.ID
}

func (m *mockKeyProvider) GetKey(ctx context.Context, id types.ID) ([]byte, error) {
	return m.key, nil
}

func (m *mockKeyProvider) GetCurrentKeyID(ctx context.Context) (types.ID, error) {
	return m.keyID, nil
}

func TestDotNotation(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	store, err := storage.NewStore(storage.Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key := make([]byte, 32)
	keyProvider := &mockKeyProvider{key: key, keyID: "test-key"}
	vault := NewVault(VaultConfig{Store: store, KeyManager: keyProvider})
	ctx := context.Background()
	creatorID := types.ID("creator")

	// Test 1: Create with dot notation
	_, err = vault.Create(ctx, CreateSecretOptions{
		Name: "mysql.host", Value: []byte("localhost"),
		Type: types.SecretTypeGeneric, CreatorID: creatorID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test 2: Get nested value
	val, err := vault.Get(ctx, "mysql.host", creatorID, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "localhost" {
		t.Errorf("Expected localhost, got %s", val)
	}

	// Test 3: Add another nested value to same parent
	_, err = vault.Create(ctx, CreateSecretOptions{
		Name: "mysql.port", Value: []byte("3306"),
		Type: types.SecretTypeGeneric, CreatorID: creatorID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test 4: Get merged parent object
	val, err = vault.Get(ctx, "mysql", creatorID, false)
	if err != nil {
		t.Fatal(err)
	}
	// Check that both host and port are present
	if !strings.Contains(string(val), `"host":"localhost"`) {
		t.Errorf("Expected host field, got %s", string(val))
	}
	if !strings.Contains(string(val), `"port":`) {
		t.Errorf("Expected port field, got %s", string(val))
	}
}
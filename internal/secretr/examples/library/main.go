package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// ExampleKeyManager is a simple implementation of secrets.KeyProvider for the library example
type ExampleKeyManager struct {
	idMgr *identity.Manager
}

func (k *ExampleKeyManager) GetKey(ctx context.Context, id types.ID) ([]byte, error) {
	// In a real scenario, this would retrieve a key from a secure store.
	// For this library example, we return a dummy key.
	return []byte("this-is-a-32-byte-dummy-key-1234"), nil
}

func (k *ExampleKeyManager) GetCurrentKeyID(ctx context.Context) (types.ID, error) {
	return "master-key-1", nil
}

func main() {
	ctx := context.Background()

	// 1. Initialize Storage
	store, err := storage.NewStore(storage.Config{
		Path: "./secretr-data",
	})
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer store.Close()

	// 2. Initialize Managers
	identityManager := identity.NewManager(identity.ManagerConfig{
		Store:          store,
		SessionTimeout: 86400000000000, // 24h in ns
	})

	keyMgr := &ExampleKeyManager{idMgr: identityManager}

	vault := secrets.NewVault(secrets.VaultConfig{
		Store:      store,
		KeyManager: keyMgr,
	})

	// 3. Create an Identity
	adminIdent, err := identityManager.CreateHumanIdentity(ctx, identity.CreateHumanOptions{
		Name:     "Library Admin",
		Email:    "admin@library.com",
		Password: "strong-password-123",
		Scopes:   []types.Scope{types.ScopeAdminAll},
	})
	if err != nil {
		log.Fatalf("Failed to create identity: %v", err)
	}
	fmt.Printf("Created identity: %s (%s)\n", adminIdent.Name, adminIdent.ID)

	// 4. Create a Secret
	secret, err := vault.Create(ctx, secrets.CreateSecretOptions{
		Name:      "api/stripe-key",
		Value:     []byte("sk_test_12345"),
		CreatorID: adminIdent.ID,
	})
	if err != nil {
		log.Fatalf("Failed to create secret: %v", err)
	}
	fmt.Printf("Created secret: %s\n", secret.Name)

	// 5. Retrieve a Secret
	val, err := vault.Get(ctx, "api/stripe-key", adminIdent.ID, false)
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Secret value: %s\n", string(val))

	// 6. Cleanup
	os.RemoveAll("./secretr-data")
}

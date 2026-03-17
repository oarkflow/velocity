package cli

import (
	"fmt"
	"path/filepath"

	"github.com/oarkflow/velocity"
)

// MasterKeyManager handles master key operations for the GUI
type MasterKeyManager struct {
	dataDir string
}

// NewMasterKeyManager creates a new master key manager
func NewMasterKeyManager(dataDir string) *MasterKeyManager {
	return &MasterKeyManager{
		dataDir: dataDir,
	}
}

// IsVaultLocked checks if the vault is locked (master key required)
func (m *MasterKeyManager) IsVaultLocked() bool {
	// Try to open the velocity database without providing a key
	// If it fails, the vault is likely locked
	config := velocity.Config{
		Path: filepath.Join(m.dataDir, "data"),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: false, // Don't cache for this check
			},
		},
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		return true // Vault is locked
	}

	// If we can open it, close it and return false
	db.Close()
	return false
}

// UnlockVault attempts to unlock the vault with the provided master key
func (m *MasterKeyManager) UnlockVault(masterKey []byte) error {
	if len(masterKey) == 0 {
		return fmt.Errorf("master key cannot be empty")
	}

	// Try to open the database with the provided key
	config := velocity.Config{
		Path: filepath.Join(m.dataDir, "data"),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: true,
				TTL:     30, // Cache for 30 seconds
			},
		},
		MasterKey: masterKey,
	}

	db, err := velocity.NewWithConfig(config)
	if err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Test the connection by performing a simple operation
	testKey := []byte("_unlock_test")
	testValue := []byte("test")

	if err := db.Put(testKey, testValue); err != nil {
		db.Close()
		return fmt.Errorf("vault unlock test failed: %w", err)
	}

	// Clean up test data
	db.Delete(testKey)
	db.Close()

	return nil
}

// GetDefaultMasterKeyManager returns a master key manager with default config
func GetDefaultMasterKeyManager() *MasterKeyManager {
	cfg := DefaultConfig()
	return NewMasterKeyManager(cfg.DataDir)
}

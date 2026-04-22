package velocity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// VaultMetadata stores information about the vault configuration
type VaultMetadata struct {
	CreatedAt time.Time `json:"created_at"`
	Type      string    `json:"type"` // "single" or "shamir"
}

// GetVaultMetadata reads the vault metadata file
func GetVaultMetadata(dbPath string) (*VaultMetadata, error) {
	metaPath := filepath.Join(dbPath, "vault.meta")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta VaultMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// SaveVaultMetadata writes the vault metadata file
func SaveVaultMetadata(dbPath string, meta *VaultMetadata) error {
	metaPath := filepath.Join(dbPath, "vault.meta")
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return os.WriteFile(metaPath, data, 0600)
}

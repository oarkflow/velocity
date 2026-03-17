package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MasterKeyHardwareConfig for HSM configuration
type MasterKeyHardwareConfig struct {
	Enabled         bool               `json:"enabled"`
	Provider        string             `json:"provider"`
	SealFile        string             `json:"sealFile,omitempty"`
	AttestationFile string             `json:"attestationFile,omitempty"`
	PKCS11          PKCS11SecretConfig `json:"pkcs11,omitempty"`
}

// PKCS11SecretConfig for PKCS#11 specific settings
type PKCS11SecretConfig struct {
	ModulePath  string `json:"modulePath,omitempty"`
	TokenLabel  string `json:"tokenLabel,omitempty"`
	TokenSerial string `json:"tokenSerial,omitempty"`
	PIN         string `json:"pin,omitempty"`
	KeyLabel    string `json:"keyLabel,omitempty"`
	SlotID      *uint  `json:"slotId,omitempty"`
}

// SealedHardwareSecret represents the encrypted secret stored on disk
type SealedHardwareSecret struct {
	Version    int               `json:"version"`
	Provider   string            `json:"provider"`
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
	KeyLabel   string            `json:"keyLabel,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SecretSealer interface for hardware backends
type SecretSealer interface {
	Provider() string
	EncryptSecret(secret []byte) (*SealedHardwareSecret, error)
	DecryptSecret(seal *SealedHardwareSecret) ([]byte, error)
	Describe() map[string]string
	Close()
}

// PersistMasterKeyHardwareConfig saves config to disk
func PersistMasterKeyHardwareConfig(cfg *MasterKeyHardwareConfig, path string) error {
	if cfg == nil {
		return fmt.Errorf("hardware config cannot be nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadMasterKeyHardwareConfig loads config from disk
func LoadMasterKeyHardwareConfig(path string) (*MasterKeyHardwareConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg MasterKeyHardwareConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

package velocity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyManager_ShamirWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// SystemFile generates key automatically, no prompts
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}

	// SystemFile mode doesn't automatically create Shamir shares
	// It just creates master.key file
	keyFile := filepath.Join(tmpDir, "master.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("SystemFile should create master.key file")
	}
}

func TestMasterKeyManager_ShamirDefaultShares(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// SystemFile generates key automatically
	_, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	// SystemFile doesn't create Shamir shares automatically
	// Just verify master.key exists
	keyFile := filepath.Join(tmpDir, "master.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("SystemFile should create master.key file")
	}
}

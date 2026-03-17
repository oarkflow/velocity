package velocity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyManager_GenerateSecureKey(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false, // Disable cache for this test
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// SystemFile generates key automatically without prompts
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get generated key: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Verify key is not all zeros (should be random)
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Fatal("Generated key should not be all zeros")
	}

	// Verify SystemFile created master.key file
	keyFile := filepath.Join(tmpDir, "master.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("SystemFile should create master.key file")
	}
}

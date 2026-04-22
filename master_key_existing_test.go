package velocity

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyManager_ExistingKeyDetection(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// Initially should not have existing key
	if manager.hasExistingKey() {
		t.Fatal("Should not detect existing key in empty directory")
	}

	// Create a WAL file to simulate existing encrypted data
	walPath := filepath.Join(tmpDir, "wal.log")
	err := os.WriteFile(walPath, []byte("dummy data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create WAL file: %v", err)
	}

	// Now should detect existing key
	if !manager.hasExistingKey() {
		t.Fatal("Should detect existing key when WAL file exists")
	}

	// Remove WAL and create SST file
	os.Remove(walPath)
	sstPath := filepath.Join(tmpDir, "sst_L0_123.db")
	err = os.WriteFile(sstPath, []byte("dummy sst data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create SST file: %v", err)
	}

	// Should still detect existing key
	if !manager.hasExistingKey() {
		t.Fatal("Should detect existing key when SST file exists")
	}
}

func TestMasterKeyManager_ExistingKeyPrompt(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// Create existing encrypted data
	walPath := filepath.Join(tmpDir, "wal.log")
	err := os.WriteFile(walPath, []byte("dummy data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create WAL file: %v", err)
	}

	// Create master.key file so SystemFile can load it
	keyPath := filepath.Join(tmpDir, "master.key")
	testKeyBytes := make([]byte, 32)
	copy(testKeyBytes, []byte("testkeyfortestingtestkeyftest32"))
	encoded := base64.StdEncoding.EncodeToString(testKeyBytes)
	if err := os.WriteFile(keyPath, []byte(encoded), 0600); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	// SystemFile should load the existing key without prompts
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get existing key: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Verify it loaded the same key
	if string(key) != string(testKeyBytes) {
		t.Fatal("Loaded key should match the one in master.key file")
	}
}

package velocity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyManager_ExistingKeyDetection(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
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
		Source: UserDefined,
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
	
	// Mock prompt to return test key
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	promptCalled := false
	manager.promptFunc = func(prompt string) (string, error) {
		promptCalled = true
		// Should be simple "Enter master key:" prompt, not generation prompt
		if prompt != "Enter master key: " {
			t.Errorf("Expected 'Enter master key: ' prompt, got: %s", prompt)
		}
		return testKey, nil
	}
	
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get existing key: %v", err)
	}
	
	if !promptCalled {
		t.Fatal("Prompt should have been called for existing key")
	}
	
	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}
}
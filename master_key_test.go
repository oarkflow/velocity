package velocity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMasterKeyManager_SystemFile(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: SystemFile,
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	// First call should create a new key file
	key1, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get master key: %v", err)
	}
	
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key1))
	}
	
	// Second call should return the same key
	key2, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get master key on second call: %v", err)
	}
	
	if string(key1) != string(key2) {
		t.Fatal("Keys should be identical between calls")
	}
	
	// Verify key file exists
	keyFile := filepath.Join(tmpDir, "master.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("Master key file should exist")
	}
}

func TestMasterKeyManager_UserDefined(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled:     true,
			TTL:         1 * time.Minute,
			MaxIdleTime: 30 * time.Second,
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	// Mock the prompt function to simulate user choosing manual entry
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	promptCount := 0
	manager.promptFunc = func(prompt string) (string, error) {
		promptCount++
		switch promptCount {
		case 1:
			return "n", nil // Don't generate, enter manually
		case 2:
			return testKey, nil // Enter test key
		case 3:
			return "n", nil // Don't use Shamir sharing
		default:
			return "", nil
		}
	}
	
	// First call should prompt and cache
	key1, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get user-defined key: %v", err)
	}
	
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key1))
	}
	
	// Second call should use cache (no prompt)
	promptCalled := false
	manager.promptFunc = func(prompt string) (string, error) {
		promptCalled = true
		return testKey, nil
	}
	
	key2, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get cached key: %v", err)
	}
	
	if promptCalled {
		t.Fatal("Prompt should not be called when key is cached")
	}
	
	if string(key1) != string(key2) {
		t.Fatal("Cached key should match original key")
	}
}

func TestMasterKeyManager_CacheExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: true,
			TTL:     100 * time.Millisecond, // Very short TTL for testing
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	promptCount := 0
	manager.promptFunc = func(prompt string) (string, error) {
		promptCount++
		switch {
		case prompt == "Generate secure MasterKey? Y/n: ":
			return "Y", nil
		case prompt == "":
			return "", nil // Press Enter
		case prompt == "Split key using Shamir sharing? Y/n: ":
			return "n", nil // Don't use Shamir
		default:
			return testKey, nil
		}
	}
	
	// Get key (should cache)
	_, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}
	
	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)
	
	// Next call should prompt again
	promptCalled := false
	manager.promptFunc = func(prompt string) (string, error) {
		promptCalled = true
		switch {
		case prompt == "Generate secure MasterKey? Y/n: ":
			return "Y", nil
		case prompt == "":
			return "", nil // Press Enter
		case prompt == "Split key using Shamir sharing? Y/n: ":
			return "n", nil // Don't use Shamir
		default:
			return testKey, nil
		}
	}
	
	_, err = manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key after expiry: %v", err)
	}
	
	if !promptCalled {
		t.Fatal("Prompt should be called after cache expiry")
	}
}

func TestMasterKeyManager_ClearCache(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: true,
			TTL:     1 * time.Minute,
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	manager.promptFunc = func(prompt string) (string, error) {
		switch {
		case prompt == "Generate secure MasterKey? Y/n: ":
			return "Y", nil
		case prompt == "":
			return "", nil // Press Enter
		case prompt == "Split key using Shamir sharing? Y/n: ":
			return "n", nil // Don't use Shamir
		default:
			return testKey, nil
		}
	}
	
	// Get and cache key
	_, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}
	
	// Clear cache
	manager.ClearCache()
	
	// Next call should prompt again
	promptCalled := false
	manager.promptFunc = func(prompt string) (string, error) {
		promptCalled = true
		switch {
		case prompt == "Generate secure MasterKey? Y/n: ":
			return "Y", nil
		case prompt == "":
			return "", nil // Press Enter
		case prompt == "Split key using Shamir sharing? Y/n: ":
			return "n", nil // Don't use Shamir
		default:
			return testKey, nil
		}
	}
	
	_, err = manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key after cache clear: %v", err)
	}
	
	if !promptCalled {
		t.Fatal("Prompt should be called after cache clear")
	}
}

func TestDB_MasterKeyOperations(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := Config{
		Path: tmpDir,
		MasterKeyConfig: MasterKeyConfig{
			Source: SystemFile,
		},
	}
	
	db, err := NewWithConfig(config)
	if err != nil {
		t.Fatalf("Failed to create DB: %v", err)
	}
	defer db.Close()
	
	// Test getting configuration
	cfg := db.GetMasterKeyConfig()
	if cfg.Source != SystemFile {
		t.Fatalf("Expected SystemFile source, got %v", cfg.Source)
	}
	
	// Test changing source
	db.SetMasterKeySource(UserDefined)
	if db.GetMasterKeySource() != UserDefined {
		t.Fatal("Source should be updated to UserDefined")
	}
	
	// Test cache info
	hasCached, _, _ := db.GetKeyCacheInfo()
	if hasCached {
		t.Fatal("Should not have cached key initially")
	}
	
	// Test clearing cache (should not error even if no cache)
	db.ClearMasterKeyCache()
}
package velocity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyManager_ShamirWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	// Mock prompts for key generation with Shamir sharing
	promptCount := 0
	manager.promptFunc = func(prompt string) (string, error) {
		promptCount++
		switch promptCount {
		case 1:
			return "Y", nil // Generate secure key
		case 2:
			return "", nil // Press Enter to confirm generated key
		case 3:
			return "Y", nil // Use Shamir sharing
		case 4:
			return "5", nil // 5 shares
		default:
			return "", nil
		}
	}
	
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key with Shamir: %v", err)
	}
	
	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}
	
	// Verify Shamir shares were created
	sharesDir := filepath.Join(tmpDir, "shamir_shares")
	if _, err := os.Stat(sharesDir); os.IsNotExist(err) {
		t.Fatal("Shamir shares directory should exist")
	}
	
	// Check for share files
	files, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatalf("Failed to read shares directory: %v", err)
	}
	
	shareCount := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".key" {
			shareCount++
		}
	}
	
	if shareCount != 5 {
		t.Fatalf("Expected 5 share files, got %d", shareCount)
	}
}

func TestMasterKeyManager_ShamirDefaultShares(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	// Mock prompts for default shares (3)
	promptCount := 0
	manager.promptFunc = func(prompt string) (string, error) {
		promptCount++
		switch promptCount {
		case 1:
			return "Y", nil // Generate secure key
		case 2:
			return "", nil // Press Enter to confirm generated key
		case 3:
			return "Y", nil // Use Shamir sharing
		case 4:
			return "", nil // Use default (3 shares)
		default:
			return "", nil
		}
	}
	
	_, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key with default Shamir: %v", err)
	}
	
	// Verify 3 shares were created (default)
	sharesDir := filepath.Join(tmpDir, "shamir_shares")
	files, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatalf("Failed to read shares directory: %v", err)
	}
	
	shareCount := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".key" {
			shareCount++
		}
	}
	
	if shareCount != 3 {
		t.Fatalf("Expected 3 share files (default), got %d", shareCount)
	}
}
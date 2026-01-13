package velocity

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMasterKeyManager_GenerateSecureKey(t *testing.T) {
	tmpDir := t.TempDir()
	
	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false, // Disable cache for this test
		},
	}
	
	manager := NewMasterKeyManager(tmpDir, config)
	
	// Mock the prompt function to simulate user choosing key generation
	promptCount := 0
	manager.promptFunc = func(prompt string) (string, error) {
		promptCount++
		switch promptCount {
		case 1:
			return "Y", nil // Generate secure key
		case 2:
			return "", nil // Press Enter to confirm
		case 3:
			return "Y", nil // Use Shamir sharing
		case 4:
			return "", nil // Use default shares (3)
		default:
			return "", nil
		}
	}
	
	// Override to capture generated key display
	originalPrompt := manager.promptFunc
	manager.promptFunc = func(prompt string) (string, error) {
		if strings.Contains(prompt, "Generate secure MasterKey") {
			return "Y", nil
		}
		if prompt == "" { // Press Enter prompt
			return "", nil
		}
		if strings.Contains(prompt, "Split key using Shamir") {
			return "Y", nil
		}
		if strings.Contains(prompt, "Number of shares") {
			return "", nil // Use default
		}
		return originalPrompt(prompt)
	}
	
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
	
	// Verify key can be base64 encoded (format check)
	encoded := base64.StdEncoding.EncodeToString(key)
	if len(encoded) == 0 {
		t.Fatal("Generated key should be encodable to base64")
	}
}
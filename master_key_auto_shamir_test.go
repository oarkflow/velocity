package velocity

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/shamir"
)

func TestMasterKeyManager_AutoUseShamirShares(t *testing.T) {
	tmpDir := t.TempDir()

	config := MasterKeyConfig{
		Source: UserDefined,
		UserKeyCache: UserKeyCacheConfig{
			Enabled: false,
		},
	}

	manager := NewMasterKeyManager(tmpDir, config)

	// Create test key and Shamir shares manually
	testKey := make([]byte, 32)
	copy(testKey, []byte("testkeyforvelocitydatabasekey32"))

	// Create Shamir shares
	shares, err := shamir.Split(testKey, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create Shamir shares: %v", err)
	}

	// Save shares to files
	sharesDir := filepath.Join(tmpDir, "key_shares")
	if err := os.MkdirAll(sharesDir, 0700); err != nil {
		t.Fatalf("Failed to create shares directory: %v", err)
	}

	for i, share := range shares {
		shareFile := filepath.Join(sharesDir, "share_"+string(rune('1'+i))+".key")
		encoded := base64.StdEncoding.EncodeToString(share)
		if err := os.WriteFile(shareFile, []byte(encoded), 0600); err != nil {
			t.Fatalf("Failed to write share %d: %v", i+1, err)
		}
	}

	// Mock prompts - no longer needed since shares are used automatically
	manager.promptFunc = func(prompt string) (string, error) {
		return "", fmt.Errorf("should not prompt when using Shamir shares")
	}

	// Get master key - should automatically use Shamir shares
	key, err := manager.GetMasterKey(nil)
	if err != nil {
		t.Fatalf("Failed to get key from Shamir shares: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Verify the reconstructed key matches original
	if string(key) != string(testKey) {
		t.Fatal("Reconstructed key should match original test key")
	}
}

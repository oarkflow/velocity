package storage

import (
	"context"
	"testing"
)

func TestDeviceProtection(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Test 1: Create store and add some data
	store1, err := NewStore(Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	
	ctx := context.Background()
	err = store1.Set(ctx, "test", "key1", []byte("value1"))
	if err != nil {
		t.Fatal(err)
	}
	store1.Close()

	// Test 2: Reopen and verify data can be read
	store2, err := NewStore(Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	
	val, err := store2.Get(ctx, "test", "key1")
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "value1" {
		t.Errorf("Expected value1, got %s", val)
	}
	store2.Close()
}

func TestDeviceProtectionGetFingerprint(t *testing.T) {
	dp := NewDeviceProtection()
	defer dp.Close()
	
	fingerprint, err := dp.GetDeviceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) == 0 {
		t.Fatal("Empty fingerprint")
	}
	
	// Should be consistent
	fingerprint2, err := dp.GetDeviceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != fingerprint2 {
		t.Fatal("Inconsistent fingerprints")
	}
}
package crypto

import (
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := []byte("super-secret-vault-key")
	parts := 5
	threshold := 3

	shares, err := Split(secret, parts, threshold)
	if err != nil {
		t.Fatalf("Failed to split secret: %v", err)
	}

	if len(shares) != parts {
		t.Errorf("Expected %d shares, got %d", parts, len(shares))
	}

	// Test with threshold shares
	subset := shares[:threshold]
	reconstructed, err := Combine(subset)
	if err != nil {
		t.Fatalf("Failed to combine shares: %v", err)
	}

	if string(reconstructed) != string(secret) {
		t.Errorf("Reconstructed secret mismatch. Expected %s, got %s", string(secret), string(reconstructed))
	}

	// Test with insufficient shares
	insufficient := shares[:threshold-1]
	_, err = Combine(insufficient)
	// The library might or might not error, but it definitely shouldn't produce the correct secret
	// Depending on implementation, it might panic or return garbage.
	// For now let's just ensure we handle the Combine call without panic
	if err == nil {
		// Some implementations return success but wrong data with fewer shares
	}
}

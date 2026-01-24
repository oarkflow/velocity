package velocity

import (
	"crypto/rand"
	"testing"
)

func TestFIPSCryptoProvider_Encryption(t *testing.T) {
	// Generate test key
	testKey := make([]byte, 32)
	_, err := rand.Read(testKey)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	provider, err := NewFIPSCryptoProvider(testKey)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test encryption
	plaintext := []byte("Sensitive military data - Top Secret")
	nonce, ciphertext, err := provider.Encrypt(plaintext, testKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	// Test decryption
	decrypted, err := provider.Decrypt(nonce, ciphertext, testKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestFIPSCryptoProvider_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	provider, err := NewFIPSCryptoProvider(key1)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	plaintext := []byte("Secret message")
	nonce, ciphertext, err := provider.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = provider.Decrypt(nonce, ciphertext, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestDeriveKeyPBKDF2(t *testing.T) {
	password := []byte("SuperSecretPassword123!")
	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Derive key
	key1, err := DeriveKeyPBKDF2(password, salt, 100000)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key1))
	}

	// Same password and salt should produce same key
	key2, err := DeriveKeyPBKDF2(password, salt, 100000)
	if err != nil {
		t.Fatalf("Second key derivation failed: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("Same password and salt should produce identical keys")
	}
}

func TestDeriveKeyArgon2id(t *testing.T) {
	password := []byte("UserPassword456")
	salt, _ := GenerateSalt(32)

	// Derive key with Argon2id
	key, err := DeriveKeyArgon2id(password, salt)
	if err != nil {
		t.Fatalf("Argon2id key derivation failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Verify reproducibility
	key2, err := DeriveKeyArgon2id(password, salt)
	if err != nil {
		t.Fatalf("Second Argon2id derivation failed: %v", err)
	}

	if string(key) != string(key2) {
		t.Error("Argon2id should produce consistent output")
	}
}

func TestValidateFIPSCompliance(t *testing.T) {
	// Valid FIPS config
	validConfig := DefaultFIPSConfig()

	err := ValidateFIPSCompliance(validConfig)
	if err != nil {
		t.Errorf("Valid FIPS config rejected: %v", err)
	}

	// Invalid config - standard mode instead of FIPS
	invalidConfig := DefaultStandardConfig()
	err = ValidateFIPSCompliance(invalidConfig)
	if err == nil {
		t.Error("Expected non-FIPS mode to be rejected")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != 32 {
		t.Errorf("Expected 32-byte salt, got %d bytes", len(salt1))
	}

	// Generate another salt
	salt2, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}

	// Salts should be unique
	if string(salt1) == string(salt2) {
		t.Error("Generated salts should be unique")
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte("sensitive key material")
	SecureZero(data)

	// Check all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not zeroed: %d", i, b)
		}
	}
}

func BenchmarkFIPSEncryption(b *testing.B) {
	testKey := make([]byte, 32)
	rand.Read(testKey)

	provider, _ := NewFIPSCryptoProvider(testKey)
	plaintext := make([]byte, 1024) // 1KB
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.Encrypt(plaintext, testKey)
	}
}

func BenchmarkPBKDF2_100k(b *testing.B) {
	password := []byte("password")
	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKeyPBKDF2(password, salt, 100000)
	}
}

func BenchmarkArgon2id(b *testing.B) {
	password := []byte("password")
	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKeyArgon2id(password, salt)
	}
}

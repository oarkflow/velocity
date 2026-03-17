package crypto

import (
	"bytes"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/security"
)

func TestEngine_GenerateKey(t *testing.T) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key, err := engine.GenerateKey(KeySize256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer key.Free()

	if key.Len() != KeySize256 {
		t.Errorf("Expected key length %d, got %d", KeySize256, key.Len())
	}
}

func TestEngine_EncryptDecrypt_AES256GCM(t *testing.T) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key, err := engine.GenerateKey(KeySize256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer key.Free()

	plaintext := []byte("Hello, Secretr! This is a test message for encryption.")
	additionalData := []byte("additional authenticated data")

	// Encrypt
	ciphertext, err := engine.Encrypt(key.Bytes(), plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Decrypt
	decrypted, err := engine.Decrypt(key.Bytes(), ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestEngine_EncryptDecrypt_ChaCha20Poly1305(t *testing.T) {
	engine := NewEngine(AlgorithmChaCha20Poly1305)
	defer engine.Close()

	key, err := engine.GenerateKey(KeySize256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer key.Free()

	plaintext := []byte("Testing ChaCha20-Poly1305 encryption.")

	ciphertext, err := engine.Encrypt(key.Bytes(), plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := engine.Decrypt(key.Bytes(), ciphertext, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted text does not match original")
	}
}

func TestEngine_DecryptWithWrongKey(t *testing.T) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key1, _ := engine.GenerateKey(KeySize256)
	key2, _ := engine.GenerateKey(KeySize256)
	defer key1.Free()
	defer key2.Free()

	plaintext := []byte("Secret message")
	ciphertext, _ := engine.Encrypt(key1.Bytes(), plaintext, nil)

	// Try to decrypt with wrong key
	_, err := engine.Decrypt(key2.Bytes(), ciphertext, nil)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestEngine_DecryptWithWrongAAD(t *testing.T) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key, _ := engine.GenerateKey(KeySize256)
	defer key.Free()

	plaintext := []byte("Secret message")
	aad1 := []byte("correct aad")
	aad2 := []byte("wrong aad")

	ciphertext, _ := engine.Encrypt(key.Bytes(), plaintext, aad1)

	// Try to decrypt with wrong AAD
	_, err := engine.Decrypt(key.Bytes(), ciphertext, aad2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong AAD")
	}
}

func TestEngine_GenerateKeyPair(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	pubKey, privKey, err := engine.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	defer privKey.Free()

	if len(pubKey) != Ed25519PubKey {
		t.Errorf("Expected public key length %d, got %d", Ed25519PubKey, len(pubKey))
	}

	if privKey.Len() != Ed25519PrivKey {
		t.Errorf("Expected private key length %d, got %d", Ed25519PrivKey, privKey.Len())
	}
}

func TestEngine_SignVerify(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	pubKey, privKey, _ := engine.GenerateKeyPair()
	defer privKey.Free()

	message := []byte("Message to sign")

	// Sign
	signature, err := engine.Sign(privKey.Bytes(), message)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify
	err = engine.Verify(pubKey, message, signature)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// Verify with wrong message should fail
	err = engine.Verify(pubKey, []byte("wrong message"), signature)
	if err == nil {
		t.Error("Expected verification to fail with wrong message")
	}
}

func TestEngine_DeriveKey(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	password := []byte("test-password-123")
	salt, _ := engine.GenerateSalt()

	key1, err := engine.DeriveKey(password, salt, KeySize256)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	defer key1.Free()

	// Derive again with same inputs should produce same key
	password2 := []byte("test-password-123")
	key2, _ := engine.DeriveKey(password2, salt, KeySize256)
	defer key2.Free()

	if !bytes.Equal(key1.Bytes(), key2.Bytes()) {
		t.Error("Same password and salt should produce same derived key")
	}

	// Different password should produce different key
	password3 := []byte("different-password")
	key3, _ := engine.DeriveKey(password3, salt, KeySize256)
	defer key3.Free()

	if bytes.Equal(key1.Bytes(), key3.Bytes()) {
		t.Error("Different passwords should produce different derived keys")
	}
}

func TestEngine_Hash(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	data := []byte("test data")

	hash1 := engine.Hash(data)
	hash2 := engine.Hash(data)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same input should produce same hash")
	}

	hash3 := engine.Hash([]byte("different data"))
	if bytes.Equal(hash1, hash3) {
		t.Error("Different input should produce different hash")
	}
}

func TestEngine_HMAC(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	key := []byte("hmac-key-123456789012345678901234")
	data := []byte("data to authenticate")

	mac1 := engine.HMAC(key, data)

	// Verify
	if !engine.VerifyHMAC(key, data, mac1) {
		t.Error("HMAC verification failed for valid MAC")
	}

	// Wrong data should fail
	if engine.VerifyHMAC(key, []byte("wrong data"), mac1) {
		t.Error("HMAC verification should fail for wrong data")
	}

	// Wrong key should fail
	if engine.VerifyHMAC([]byte("wrong-key-12345678901234567890123"), data, mac1) {
		t.Error("HMAC verification should fail for wrong key")
	}
}

func TestEngine_HashChain(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	prevHash := []byte("previous-hash-value-32-bytes!!")
	data := []byte("event data")

	hash1 := engine.HashChain(prevHash, data)
	hash2 := engine.HashChain(prevHash, data)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same inputs should produce same hash chain")
	}

	// Different previous hash should produce different result
	hash3 := engine.HashChain([]byte("different-previous-hash-32!!!!"), data)
	if bytes.Equal(hash1, hash3) {
		t.Error("Different previous hash should produce different chain")
	}
}

func TestEngine_X25519KeyExchange(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	// Generate key pairs for Alice and Bob
	alicePub, alicePriv, _ := engine.GenerateX25519KeyPair()
	bobPub, bobPriv, _ := engine.GenerateX25519KeyPair()
	defer alicePriv.Free()
	defer bobPriv.Free()

	// Compute shared secrets
	aliceShared, err := engine.ComputeSharedSecret(alicePriv.Bytes(), bobPub)
	if err != nil {
		t.Fatalf("Alice's shared secret computation failed: %v", err)
	}
	defer aliceShared.Free()

	bobShared, err := engine.ComputeSharedSecret(bobPriv.Bytes(), alicePub)
	if err != nil {
		t.Fatalf("Bob's shared secret computation failed: %v", err)
	}
	defer bobShared.Free()

	// Both should arrive at same shared secret
	if !bytes.Equal(aliceShared.Bytes(), bobShared.Bytes()) {
		t.Error("Shared secrets should be equal")
	}
}

func TestEnvelopeEncryption(t *testing.T) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	envelope := NewEnvelopeEncryption(engine)

	kek, _ := engine.GenerateKey(KeySize256)
	defer kek.Free()

	plaintext := []byte("Sensitive data to protect with envelope encryption")
	additionalData := []byte("metadata")

	// Encrypt
	encrypted, err := envelope.Encrypt(kek.Bytes(), "key-123", plaintext, additionalData)
	if err != nil {
		t.Fatalf("Envelope encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := envelope.Decrypt(kek.Bytes(), encrypted, additionalData)
	if err != nil {
		t.Fatalf("Envelope decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match original")
	}
}

func TestTimeBoundKey(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	// Create key valid for 1 hour
	tbk, err := engine.NewTimeBoundKey(1 * 60 * 60 * 1000000000) // 1 hour in nanoseconds
	if err != nil {
		t.Fatalf("Failed to create time-bound key: %v", err)
	}
	defer tbk.Destroy()

	if !tbk.IsValid() {
		t.Error("Newly created time-bound key should be valid")
	}

	if tbk.Key == nil {
		t.Error("Time-bound key should have key material")
	}
}

func TestEngine_Fingerprint(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	data := []byte("some data to fingerprint")

	fp1 := engine.Fingerprint(data)
	fp2 := engine.Fingerprint(data)

	if fp1 != fp2 {
		t.Error("Same data should produce same fingerprint")
	}

	fp3 := engine.Fingerprint([]byte("different data"))
	if fp1 == fp3 {
		t.Error("Different data should produce different fingerprint")
	}

	// Fingerprint should be hex string
	if len(fp1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("Fingerprint should be 32 hex chars, got %d", len(fp1))
	}
}

func TestEngine_GenerateRandomID(t *testing.T) {
	engine := NewEngine("")
	defer engine.Close()

	id1, err := engine.GenerateRandomID()
	if err != nil {
		t.Fatalf("Failed to generate random ID: %v", err)
	}

	id2, _ := engine.GenerateRandomID()

	if id1 == id2 {
		t.Error("Random IDs should be unique")
	}

	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("ID should be 32 hex chars, got %d", len(id1))
	}
}

// Benchmarks

func BenchmarkEncrypt_AES256GCM(b *testing.B) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key, _ := engine.GenerateKey(KeySize256)
	defer key.Free()

	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Encrypt(key.Bytes(), plaintext, nil)
	}
}

func BenchmarkDecrypt_AES256GCM(b *testing.B) {
	engine := NewEngine(AlgorithmAES256GCM)
	defer engine.Close()

	key, _ := engine.GenerateKey(KeySize256)
	defer key.Free()

	plaintext := make([]byte, 1024)
	ciphertext, _ := engine.Encrypt(key.Bytes(), plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Decrypt(key.Bytes(), ciphertext, nil)
	}
}

func BenchmarkEncrypt_ChaCha20Poly1305(b *testing.B) {
	engine := NewEngine(AlgorithmChaCha20Poly1305)
	defer engine.Close()

	key, _ := engine.GenerateKey(KeySize256)
	defer key.Free()

	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Encrypt(key.Bytes(), plaintext, nil)
	}
}

func BenchmarkDeriveKey_Argon2id(b *testing.B) {
	engine := NewEngine("")
	defer engine.Close()

	password := []byte("benchmark-password")
	salt, _ := engine.GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, _ := engine.DeriveKey(password, salt, KeySize256)
		key.Free()
	}
}

func BenchmarkSign_Ed25519(b *testing.B) {
	engine := NewEngine("")
	defer engine.Close()

	_, privKey, _ := engine.GenerateKeyPair()
	defer privKey.Free()

	message := []byte("message to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Sign(privKey.Bytes(), message)
	}
}

func BenchmarkVerify_Ed25519(b *testing.B) {
	engine := NewEngine("")
	defer engine.Close()

	pubKey, privKey, _ := engine.GenerateKeyPair()
	defer privKey.Free()

	message := []byte("message to verify")
	signature, _ := engine.Sign(privKey.Bytes(), message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Verify(pubKey, message, signature)
	}
}

func BenchmarkHash_SHA256(b *testing.B) {
	engine := NewEngine("")
	defer engine.Close()

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Hash(data)
	}
}

// Security Tests

func TestSecureBytes_Zeroization(t *testing.T) {
	data := []byte("sensitive data that must be zeroized")
	original := make([]byte, len(data))
	copy(original, data)

	security.Zeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at position %d was not zeroized: got %d", i, b)
		}
	}
}

func TestSecureBytes_ConstantTimeCompare(t *testing.T) {
	a := []byte("test-value-12345")
	b := []byte("test-value-12345")
	c := []byte("different-value!")

	if !security.ConstantTimeCompare(a, b) {
		t.Error("Equal values should return true")
	}

	if security.ConstantTimeCompare(a, c) {
		t.Error("Different values should return false")
	}
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	encryptedBenchmarkStartID  = 2_000_000
	encryptedBenchmarkCount    = 10_000
	encryptedBenchmarkTargetID = encryptedBenchmarkStartID + 42
)

var benchmarkEncryptionKey = []byte("0123456789abcdef0123456789abcdef")

type benchmarkUser struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Age   int    `json:"age"`
}

func benchmarkEmail(id int) string {
	return fmt.Sprintf("user_%d@example.com", id)
}

func benchmarkUserRecord(id int, name string, age int) benchmarkUser {
	return benchmarkUser{
		ID:    id,
		Name:  name,
		Email: benchmarkEmail(id),
		Age:   age,
	}
}

func benchmarkUserJSON(id int, name string, age int) ([]byte, error) {
	return json.Marshal(benchmarkUserRecord(id, name, age))
}

func benchmarkDerivedHash(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func encryptBenchmarkPayload(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

func decryptBenchmarkPayload(key, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

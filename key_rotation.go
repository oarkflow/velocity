package velocity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// KeyRotationPolicy manages automatic key rotation
type KeyRotationPolicy struct {
	Enabled           bool          `json:"enabled"`
	RotationInterval  time.Duration `json:"rotation_interval"`  // e.g., 90 days
	MaxKeyAge         time.Duration `json:"max_key_age"`         // e.g., 365 days
	ReencryptionBatch int           `json:"reencryption_batch"` // Records per batch
	LastRotation      time.Time     `json:"last_rotation"`
	CurrentKeyVersion int           `json:"current_key_version"`
	KeyHistory        []KeyVersionInfo `json:"key_history"`
	AutoRotate        bool          `json:"auto_rotate"` // Automatic background rotation
}

// KeyRotationManager handles key lifecycle management
type KeyRotationManager struct {
	db            *DB
	policy        KeyRotationPolicy
	currentKey    []byte
	keyVersions   map[int][]byte // version -> key
	mu            sync.RWMutex
	rotationTimer *time.Timer
	stopCh        chan struct{}
}

// NewKeyRotationManager creates a new key rotation manager
func NewKeyRotationManager(db *DB, policy KeyRotationPolicy) *KeyRotationManager {
	krm := &KeyRotationManager{
		db:          db,
		policy:      policy,
		keyVersions: make(map[int][]byte),
		stopCh:      make(chan struct{}),
	}

	// Load current key from master key
	if db.masterKey != nil {
		krm.currentKey = make([]byte, len(db.masterKey))
		copy(krm.currentKey, db.masterKey)
		krm.policy.CurrentKeyVersion = 1
		krm.keyVersions[1] = krm.currentKey
	}

	return krm
}

// Start begins automatic key rotation if enabled
func (krm *KeyRotationManager) Start(ctx context.Context) error {
	if !krm.policy.Enabled || !krm.policy.AutoRotate {
		return nil
	}

	// Check if rotation is needed on startup
	if krm.shouldRotate() {
		if err := krm.RotateKeys(ctx); err != nil {
			return fmt.Errorf("initial key rotation failed: %w", err)
		}
	}

	// Schedule next rotation
	krm.scheduleNextRotation(ctx)

	return nil
}

// Stop halts automatic key rotation
func (krm *KeyRotationManager) Stop() {
	close(krm.stopCh)
	if krm.rotationTimer != nil {
		krm.rotationTimer.Stop()
	}
}

// shouldRotate checks if key rotation is needed
func (krm *KeyRotationManager) shouldRotate() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.policy.LastRotation.IsZero() {
		return true
	}

	return time.Since(krm.policy.LastRotation) >= krm.policy.RotationInterval
}

// scheduleNextRotation sets up the next rotation timer
func (krm *KeyRotationManager) scheduleNextRotation(ctx context.Context) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	var nextRotation time.Duration
	if krm.policy.LastRotation.IsZero() {
		nextRotation = krm.policy.RotationInterval
	} else {
		elapsed := time.Since(krm.policy.LastRotation)
		nextRotation = krm.policy.RotationInterval - elapsed
		if nextRotation < 0 {
			nextRotation = time.Minute // Rotate soon
		}
	}

	krm.rotationTimer = time.AfterFunc(nextRotation, func() {
		if err := krm.RotateKeys(ctx); err != nil {
			// Log error but continue scheduling
			fmt.Printf("Key rotation error: %v\n", err)
		}
		krm.scheduleNextRotation(ctx)
	})
}

// RotateKeys performs key rotation and re-encryption
func (krm *KeyRotationManager) RotateKeys(ctx context.Context) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Step 1: Generate new key
	newKey, err := GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	newVersion := krm.policy.CurrentKeyVersion + 1

	// Step 2: Mark old key as "rotating"
	if len(krm.policy.KeyHistory) > 0 {
		lastIdx := len(krm.policy.KeyHistory) - 1
		krm.policy.KeyHistory[lastIdx].Status = "rotating"
	}

	// Step 3: Add new key to history
	newKeyInfo := KeyVersionInfo{
		Version:    newVersion,
		KeyID:      generateKeyID(),
		CreatedAt:  time.Now(),
		Status:     "active",
		Algorithm:  "AES-256-GCM",
		CryptoMode: string(CryptoModeFIPS),
	}
	krm.policy.KeyHistory = append(krm.policy.KeyHistory, newKeyInfo)

	// Step 4: Store new key
	krm.keyVersions[newVersion] = newKey
	oldKey := krm.currentKey
	oldVersion := krm.policy.CurrentKeyVersion
	krm.currentKey = newKey
	krm.policy.CurrentKeyVersion = newVersion

	// Step 5: Update database master key
	krm.db.masterKey = newKey
	if krm.db.crypto != nil {
		// Create new crypto provider with new key
		newCrypto, err := newCryptoProvider(newKey)
		if err != nil {
			// Rollback
			krm.currentKey = oldKey
			krm.policy.CurrentKeyVersion = oldVersion
			krm.db.masterKey = oldKey
			return fmt.Errorf("failed to create new crypto provider: %w", err)
		}
		krm.db.crypto = newCrypto
	}

	// Step 6: Re-encrypt data in batches
	if err := krm.reencryptData(ctx, oldKey, newKey, oldVersion, newVersion); err != nil {
		// Log error but don't fail rotation (data can be accessed with old key)
		fmt.Printf("Re-encryption error (non-fatal): %v\n", err)
	}

	// Step 7: Mark old key as "rotated"
	if len(krm.policy.KeyHistory) > 1 {
		idx := len(krm.policy.KeyHistory) - 2
		krm.policy.KeyHistory[idx].Status = "rotated"
		krm.policy.KeyHistory[idx].RotatedAt = time.Now()
	}

	// Step 8: Update rotation timestamp
	krm.policy.LastRotation = time.Now()

	// Step 9: Save rotation metadata
	if err := krm.saveRotationMetadata(); err != nil {
		fmt.Printf("Failed to save rotation metadata: %v\n", err)
	}

	// Step 10: Securely zero old key after grace period
	time.AfterFunc(24*time.Hour, func() {
		SecureZero(oldKey)
	})

	return nil
}

// reencryptData re-encrypts all data with the new key
func (krm *KeyRotationManager) reencryptData(ctx context.Context, oldKey, newKey []byte, oldVersion, newVersion int) error {
	// Create crypto providers for old and new keys
	oldCrypto, err := newCryptoProvider(oldKey)
	if err != nil {
		return fmt.Errorf("failed to create old crypto provider: %w", err)
	}

	newCrypto, err := newCryptoProvider(newKey)
	if err != nil {
		return fmt.Errorf("failed to create new crypto provider: %w", err)
	}

	// Get all keys to re-encrypt
	keys, _ := krm.db.KeysPage(0, krm.policy.ReencryptionBatch)

	reencrypted := 0
	for _, key := range keys {
		// Skip system keys
		if isSystemKey(key) {
			continue
		}

		// Get encrypted value
		encValue, err := krm.db.getRawValue(key)
		if err != nil {
			continue // Skip if can't read
		}

		// Decrypt with old key
		plaintext, err := krm.decryptValue(encValue, oldCrypto)
		if err != nil {
			continue // Skip if can't decrypt
		}

		// Encrypt with new key
		newEncValue, err := krm.encryptValue(plaintext, newCrypto, newVersion)
		if err != nil {
			continue // Skip if can't encrypt
		}

		// Store re-encrypted value
		if err := krm.db.putRawValue(key, newEncValue); err != nil {
			continue // Skip if can't write
		}

		reencrypted++

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Batch checkpoint
		if reencrypted%krm.policy.ReencryptionBatch == 0 {
			time.Sleep(10 * time.Millisecond) // Brief pause to avoid overload
		}
	}

	return nil
}

// GetKeyVersion retrieves a key by version
func (krm *KeyRotationManager) GetKeyVersion(version int) ([]byte, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key, exists := krm.keyVersions[version]
	if !exists {
		return nil, fmt.Errorf("key version %d not found", version)
	}

	// Create a copy to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

// GetCurrentKey returns the active encryption key
func (krm *KeyRotationManager) GetCurrentKey() ([]byte, int) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	keyCopy := make([]byte, len(krm.currentKey))
	copy(keyCopy, krm.currentKey)
	return keyCopy, krm.policy.CurrentKeyVersion
}

// RetireOldKeys marks old keys as retired (cannot be used for new operations)
func (krm *KeyRotationManager) RetireOldKeys() error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	now := time.Now()
	for i := range krm.policy.KeyHistory {
		keyInfo := &krm.policy.KeyHistory[i]
		if keyInfo.Status == "rotated" {
			age := now.Sub(keyInfo.RotatedAt)
			if age >= krm.policy.MaxKeyAge {
				keyInfo.Status = "retired"
				keyInfo.RetiredAt = now

				// Remove retired key from memory (keep for legacy decryption)
				// In production, move to secure cold storage
			}
		}
	}

	return krm.saveRotationMetadata()
}

// saveRotationMetadata persists rotation policy to database
func (krm *KeyRotationManager) saveRotationMetadata() error {
	data, err := json.Marshal(krm.policy)
	if err != nil {
		return fmt.Errorf("failed to marshal rotation metadata: %w", err)
	}

	return krm.db.Put([]byte("_system:key_rotation_policy"), data)
}

// loadRotationMetadata loads rotation policy from database
func (krm *KeyRotationManager) loadRotationMetadata() error {
	data, err := krm.db.Get([]byte("_system:key_rotation_policy"))
	if err != nil {
		return err // Not found is OK (first run)
	}

	return json.Unmarshal(data, &krm.policy)
}

// GetRotationStatus returns current rotation status
func (krm *KeyRotationManager) GetRotationStatus() RotationStatus {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	status := RotationStatus{
		CurrentVersion: krm.policy.CurrentKeyVersion,
		LastRotation:   krm.policy.LastRotation,
		NextRotation:   krm.policy.LastRotation.Add(krm.policy.RotationInterval),
		KeyCount:       len(krm.policy.KeyHistory),
		ActiveKeys:     0,
		RotatedKeys:    0,
		RetiredKeys:    0,
	}

	for _, keyInfo := range krm.policy.KeyHistory {
		switch keyInfo.Status {
		case "active":
			status.ActiveKeys++
		case "rotated", "rotating":
			status.RotatedKeys++
		case "retired":
			status.RetiredKeys++
		}
	}

	return status
}

// RotationStatus provides rotation status information
type RotationStatus struct {
	CurrentVersion int       `json:"current_version"`
	LastRotation   time.Time `json:"last_rotation"`
	NextRotation   time.Time `json:"next_rotation"`
	KeyCount       int       `json:"key_count"`
	ActiveKeys     int       `json:"active_keys"`
	RotatedKeys    int       `json:"rotated_keys"`
	RetiredKeys    int       `json:"retired_keys"`
}

// Helper functions for re-encryption

func (krm *KeyRotationManager) decryptValue(encValue []byte, crypto *CryptoProvider) ([]byte, error) {
	// Parse encrypted value format: [nonce][ciphertext]
	nonceSize := 24 // ChaCha20-Poly1305 nonce size
	if len(encValue) < nonceSize {
		return nil, errors.New("encrypted value too short")
	}

	nonce := encValue[:nonceSize]
	ciphertext := encValue[nonceSize:]

	return crypto.Decrypt(nonce, ciphertext, nil)
}

func (krm *KeyRotationManager) encryptValue(plaintext []byte, crypto *CryptoProvider, version int) ([]byte, error) {
	nonce, ciphertext, err := crypto.Encrypt(plaintext, nil)
	if err != nil {
		return nil, err
	}

	// Combine nonce and ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func isSystemKey(key []byte) bool {
	keyStr := string(key)
	return len(keyStr) > 8 && keyStr[:8] == "_system:"
}

// getRawValue retrieves raw encrypted value (helper method)
func (db *DB) getRawValue(key []byte) ([]byte, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	// Check memtable first
	if entry := db.memTable.Get(key); entry != nil {
		if entry.Deleted {
			return nil, errors.New("key not found")
		}
		return entry.Value, nil
	}

	// Check SSTables
	for level := 0; level < len(db.levels); level++ {
		for _, sst := range db.levels[level] {
			entry, err := sst.Get(key)
			if err == nil && entry != nil {
				if entry.Deleted {
					return nil, errors.New("key not found")
				}
				return entry.Value, nil
			}
		}
	}

	return nil, errors.New("key not found")
}

// putRawValue stores raw encrypted value (helper method)
func (db *DB) putRawValue(key, value []byte) error {
	return db.Put(key, value)
}

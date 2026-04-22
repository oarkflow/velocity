package velocity

import (
	"fmt"
	"time"
)

// GetMasterKeyConfig returns the current master key configuration
func (db *DB) GetMasterKeyConfig() MasterKeyConfig {
	return db.masterKeyManager.config
}

// SetMasterKeyConfig updates the master key configuration
func (db *DB) SetMasterKeyConfig(config MasterKeyConfig) {
	db.masterKeyManager.config = config
}

// ClearMasterKeyCache clears any cached user-defined master key
func (db *DB) ClearMasterKeyCache() {
	db.masterKeyManager.ClearCache()
}

// RefreshMasterKey forces a refresh of the master key (useful for user-defined keys)
func (db *DB) RefreshMasterKey() error {
	// Clear cache to force re-prompt
	db.masterKeyManager.ClearCache()
	
	// Get new key
	key, err := db.masterKeyManager.GetMasterKey(nil)
	if err != nil {
		return fmt.Errorf("failed to refresh master key: %w", err)
	}
	
	// Update crypto provider
	newCrypto, err := newCryptoProvider(key)
	if err != nil {
		return fmt.Errorf("failed to create crypto provider: %w", err)
	}
	
	db.mutex.Lock()
	db.crypto = newCrypto
	db.mutex.Unlock()
	
	return nil
}

// GetMasterKeySource returns the current master key source
func (db *DB) GetMasterKeySource() MasterKeySource {
	return db.masterKeyManager.config.Source
}

// SetMasterKeySource changes the master key source
func (db *DB) SetMasterKeySource(source MasterKeySource) {
	db.masterKeyManager.config.Source = source
	// Clear cache when changing source
	db.masterKeyManager.ClearCache()
}

// GetKeyCacheInfo returns information about the key cache
func (db *DB) GetKeyCacheInfo() (bool, time.Time, time.Time) {
	db.masterKeyManager.cacheMutex.RLock()
	defer db.masterKeyManager.cacheMutex.RUnlock()
	
	hasCachedKey := db.masterKeyManager.cachedKey != nil
	return hasCachedKey, db.masterKeyManager.cacheExpiry, db.masterKeyManager.lastAccess
}

// SetUserKeyCacheConfig updates user key cache settings
func (db *DB) SetUserKeyCacheConfig(config UserKeyCacheConfig) {
	db.masterKeyManager.config.UserKeyCache = config
	
	// If caching is disabled, clear existing cache
	if !config.Enabled {
		db.masterKeyManager.ClearCache()
	}
}

// SetShamirConfig updates Shamir secret sharing configuration
func (db *DB) SetShamirConfig(config ShamirSecretConfig) {
	db.masterKeyManager.config.ShamirConfig = config
}
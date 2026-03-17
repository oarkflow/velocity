package velocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// DataClassKeyManager manages encryption keys per data classification.
type DataClassKeyManager struct {
	db *DB
}

// NewDataClassKeyManager creates a new manager.
func NewDataClassKeyManager(db *DB) *DataClassKeyManager {
	return &DataClassKeyManager{db: db}
}

// GetKeyForClass returns a derived key for a data class.
func (km *DataClassKeyManager) GetKeyForClass(class DataClassification) ([]byte, int, error) {
	version, err := km.getVersion(class)
	if err != nil {
		return nil, 0, err
	}
	key := km.deriveKey(class, version)
	return key, version, nil
}

// RotateKey increments key version for a data class.
func (km *DataClassKeyManager) RotateKey(class DataClassification) (int, error) {
	version, err := km.getVersion(class)
	if err != nil {
		return 0, err
	}
	version++
	if err := km.setVersion(class, version); err != nil {
		return 0, err
	}
	return version, nil
}

func (km *DataClassKeyManager) getVersion(class DataClassification) (int, error) {
	key := []byte(fmt.Sprintf("dataclass:key:%s:version", class))
	data, err := km.db.Get(key)
	if err != nil {
		// default to version 1
		_ = km.setVersion(class, 1)
		return 1, nil
	}
	var v int
	if _, err := fmt.Sscanf(string(data), "%d", &v); err != nil {
		return 0, err
	}
	if v == 0 {
		v = 1
	}
	return v, nil
}

func (km *DataClassKeyManager) setVersion(class DataClassification, version int) error {
	key := []byte(fmt.Sprintf("dataclass:key:%s:version", class))
	return km.db.Put(key, []byte(fmt.Sprintf("%d", version)))
}

func (km *DataClassKeyManager) deriveKey(class DataClassification, version int) []byte {
	// Use master key material with class+version for deterministic derivation
	seed := fmt.Sprintf("%s:%d", class, version)
	master := km.db.masterKey
	h := sha256.New()
	h.Write(master)
	h.Write([]byte(seed))
	sum := h.Sum(nil)
	return sum
}

// RotateKeyWithAudit rotates a data-class key and logs to audit trail.
func (km *DataClassKeyManager) RotateKeyWithAudit(ctx context.Context, class DataClassification, audit *AuditLogManager) (int, error) {
	version, err := km.RotateKey(class)
	if err != nil {
		return 0, err
	}
	if audit != nil {
		_ = audit.LogEvent(AuditEvent{
			Timestamp: time.Now(),
			Actor:     "key_rotation_system",
			Action:    "data_class_key_rotate",
			Resource:  fmt.Sprintf("data_class:%s", class),
			Result:    "success",
		})
	}
	return version, nil
}

// KeyID returns a stable identifier for the derived key.
func (km *DataClassKeyManager) KeyID(class DataClassification, version int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", class, version)))
	return hex.EncodeToString(sum[:8])
}

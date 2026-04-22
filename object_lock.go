package velocity

import (
	"encoding/json"
	"fmt"
	"time"
)

// Object Lock (WORM) implementation - S3-compatible

// ObjectLockMode defines the retention mode
type ObjectLockMode string

const (
	// LockModeGovernance allows bypass by privileged users
	LockModeGovernance ObjectLockMode = "GOVERNANCE"
	// LockModeCompliance is irrevocable - no one can bypass
	LockModeCompliance ObjectLockMode = "COMPLIANCE"
)

const (
	lockConfigPrefix    = "lock:config:"
	lockRetentionPrefix = "lock:retention:"
	lockHoldPrefix      = "lock:hold:"
)

// ObjectLockConfig represents bucket-level Object Lock configuration
type ObjectLockConfig struct {
	Enabled          bool           `json:"enabled"`
	DefaultRetention *ObjectLockRetentionRule `json:"default_retention,omitempty"`
}

// ObjectLockRetentionRule defines default retention for a bucket
type ObjectLockRetentionRule struct {
	Mode  ObjectLockMode `json:"mode"`
	Days  int            `json:"days,omitempty"`
	Years int            `json:"years,omitempty"`
}

// ObjectRetention represents retention settings for a specific object
type ObjectRetention struct {
	Mode            ObjectLockMode `json:"mode"`
	RetainUntilDate time.Time      `json:"retain_until_date"`
}

// ObjectLegalHold represents a legal hold on an object
type ObjectLegalHold struct {
	Status string `json:"status"` // "ON" or "OFF"
}

// ObjectLockManager manages WORM compliance
type ObjectLockManager struct {
	db *DB
}

// NewObjectLockManager creates a new object lock manager
func NewObjectLockManager(db *DB) *ObjectLockManager {
	return &ObjectLockManager{db: db}
}

// SetBucketObjectLock configures Object Lock for a bucket
func (olm *ObjectLockManager) SetBucketObjectLock(bucket string, config ObjectLockConfig) error {
	if config.DefaultRetention != nil {
		if config.DefaultRetention.Mode != LockModeGovernance && config.DefaultRetention.Mode != LockModeCompliance {
			return fmt.Errorf("invalid retention mode: %s", config.DefaultRetention.Mode)
		}
		if config.DefaultRetention.Days <= 0 && config.DefaultRetention.Years <= 0 {
			return fmt.Errorf("retention must specify days or years")
		}
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	return olm.db.PutWithTTL([]byte(lockConfigPrefix+bucket), data, 0)
}

// GetBucketObjectLock retrieves Object Lock configuration for a bucket
func (olm *ObjectLockManager) GetBucketObjectLock(bucket string) (*ObjectLockConfig, error) {
	data, err := olm.db.Get([]byte(lockConfigPrefix + bucket))
	if err != nil {
		return &ObjectLockConfig{}, nil
	}

	var config ObjectLockConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SetObjectRetention sets retention on a specific object
func (olm *ObjectLockManager) SetObjectRetention(bucket, key string, retention ObjectRetention) error {
	if retention.Mode != LockModeGovernance && retention.Mode != LockModeCompliance {
		return fmt.Errorf("invalid retention mode: %s", retention.Mode)
	}

	if retention.RetainUntilDate.IsZero() {
		return fmt.Errorf("retain until date is required")
	}

	if retention.RetainUntilDate.Before(time.Now()) {
		return fmt.Errorf("retain until date must be in the future")
	}

	// Check existing retention - COMPLIANCE mode cannot be shortened
	existing, err := olm.GetObjectRetention(bucket, key)
	if err == nil && existing != nil {
		if existing.Mode == LockModeCompliance {
			if retention.RetainUntilDate.Before(existing.RetainUntilDate) {
				return fmt.Errorf("cannot shorten COMPLIANCE mode retention period")
			}
		}
	}

	data, err := json.Marshal(retention)
	if err != nil {
		return err
	}

	retentionKey := lockRetentionPrefix + bucket + "/" + key
	return olm.db.PutWithTTL([]byte(retentionKey), data, 0)
}

// GetObjectRetention retrieves retention settings for an object
func (olm *ObjectLockManager) GetObjectRetention(bucket, key string) (*ObjectRetention, error) {
	retentionKey := lockRetentionPrefix + bucket + "/" + key
	data, err := olm.db.Get([]byte(retentionKey))
	if err != nil {
		return nil, nil // No retention set
	}

	var retention ObjectRetention
	if err := json.Unmarshal(data, &retention); err != nil {
		return nil, err
	}

	return &retention, nil
}

// SetObjectLegalHold sets or removes a legal hold on an object
func (olm *ObjectLockManager) SetObjectLegalHold(bucket, key string, hold ObjectLegalHold) error {
	if hold.Status != "ON" && hold.Status != "OFF" {
		return fmt.Errorf("legal hold status must be ON or OFF")
	}

	data, err := json.Marshal(hold)
	if err != nil {
		return err
	}

	holdKey := lockHoldPrefix + bucket + "/" + key
	return olm.db.PutWithTTL([]byte(holdKey), data, 0)
}

// GetObjectLegalHold retrieves legal hold status for an object
func (olm *ObjectLockManager) GetObjectLegalHold(bucket, key string) (*ObjectLegalHold, error) {
	holdKey := lockHoldPrefix + bucket + "/" + key
	data, err := olm.db.Get([]byte(holdKey))
	if err != nil {
		return &ObjectLegalHold{Status: "OFF"}, nil
	}

	var hold ObjectLegalHold
	if err := json.Unmarshal(data, &hold); err != nil {
		return nil, err
	}

	return &hold, nil
}

// IsObjectLocked checks if an object is currently locked (by retention or legal hold)
func (olm *ObjectLockManager) IsObjectLocked(bucket, key string) (bool, error) {
	// Check legal hold
	hold, err := olm.GetObjectLegalHold(bucket, key)
	if err != nil {
		return false, err
	}
	if hold != nil && hold.Status == "ON" {
		return true, nil
	}

	// Check retention
	retention, err := olm.GetObjectRetention(bucket, key)
	if err != nil {
		return false, err
	}
	if retention != nil && time.Now().Before(retention.RetainUntilDate) {
		return true, nil
	}

	// Check bucket-level default retention
	config, err := olm.GetBucketObjectLock(bucket)
	if err != nil {
		return false, err
	}
	if config != nil && config.Enabled && config.DefaultRetention != nil {
		// Default retention applies if no object-level retention is set
		if retention == nil {
			return true, nil
		}
	}

	return false, nil
}

// CanDeleteObject checks if an object can be deleted considering locks
// Returns: (allowed, reason, error)
func (olm *ObjectLockManager) CanDeleteObject(bucket, key, user string, bypassGovernance bool) (bool, string, error) {
	// Check legal hold first - no one can bypass
	hold, err := olm.GetObjectLegalHold(bucket, key)
	if err != nil {
		return false, "", err
	}
	if hold != nil && hold.Status == "ON" {
		return false, "object is under legal hold", nil
	}

	// Check retention
	retention, err := olm.GetObjectRetention(bucket, key)
	if err != nil {
		return false, "", err
	}

	if retention != nil && time.Now().Before(retention.RetainUntilDate) {
		switch retention.Mode {
		case LockModeCompliance:
			// COMPLIANCE: absolutely no one can delete
			return false, fmt.Sprintf("object is locked in COMPLIANCE mode until %s", retention.RetainUntilDate.Format(time.RFC3339)), nil
		case LockModeGovernance:
			// GOVERNANCE: can bypass with special permission
			if bypassGovernance {
				return true, "", nil
			}
			return false, fmt.Sprintf("object is locked in GOVERNANCE mode until %s (use bypass to override)", retention.RetainUntilDate.Format(time.RFC3339)), nil
		}
	}

	return true, "", nil
}

// ApplyDefaultRetention applies bucket-level default retention to a new object
func (olm *ObjectLockManager) ApplyDefaultRetention(bucket, key string) error {
	config, err := olm.GetBucketObjectLock(bucket)
	if err != nil || config == nil || !config.Enabled || config.DefaultRetention == nil {
		return nil
	}

	var retainUntil time.Time
	now := time.Now().UTC()

	if config.DefaultRetention.Days > 0 {
		retainUntil = now.AddDate(0, 0, config.DefaultRetention.Days)
	} else if config.DefaultRetention.Years > 0 {
		retainUntil = now.AddDate(config.DefaultRetention.Years, 0, 0)
	} else {
		return nil
	}

	retention := ObjectRetention{
		Mode:            config.DefaultRetention.Mode,
		RetainUntilDate: retainUntil,
	}

	return olm.SetObjectRetention(bucket, key, retention)
}

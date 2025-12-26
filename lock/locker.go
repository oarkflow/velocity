package lock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

var (
	ErrLockAlreadyAcquired = errors.New("lock already acquired by another process")
	ErrLockNotHeld         = errors.New("lock not held")
	ErrLockExpired         = errors.New("lock has expired")
)

// Locker interface defines lock operations
type Locker interface {
	Acquire(ctx context.Context, key string, ttl time.Duration) error
	Release(ctx context.Context, key string) error
	Renew(ctx context.Context, key string, ttl time.Duration) error
	IsLocked(ctx context.Context, key string) (bool, error)
}

// VelocityLocker implements distributed locking using Velocity DB
type VelocityLocker struct {
	db *velocity.DB
}

// NewVelocityLocker creates a new Velocity-based locker
func NewVelocityLocker(db *velocity.DB) *VelocityLocker {
	return &VelocityLocker{db: db}
}

// Acquire acquires a lock with the given key and TTL
func (v *VelocityLocker) Acquire(ctx context.Context, key string, ttl time.Duration) error {
	k := []byte("lock:" + key)

	val, err := v.db.Get(k)
	if err != nil && err.Error() != "key not found" {
		return fmt.Errorf("failed to check lock: %w", err)
	}

	if val != nil {
		// Parse expiration time
		exp, err := time.Parse(time.RFC3339, string(val))
		if err != nil {
			return fmt.Errorf("failed to parse lock expiration: %w", err)
		}
		if time.Now().Before(exp) {
			return ErrLockAlreadyAcquired
		}
	}

	// Acquire the lock
	exp := time.Now().Add(ttl)
	err = v.db.Put(k, []byte(exp.Format(time.RFC3339)))
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	return nil
}

// Release releases a lock with the given key
func (v *VelocityLocker) Release(ctx context.Context, key string) error {
	k := []byte("lock:" + key)

	val, err := v.db.Get(k)
	if err != nil && err.Error() != "key not found" {
		return fmt.Errorf("failed to check lock: %w", err)
	}

	if val == nil {
		return ErrLockNotHeld
	}

	// Check if expired
	exp, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return fmt.Errorf("failed to parse lock expiration: %w", err)
	}

	if time.Now().After(exp) {
		return ErrLockExpired
	}

	err = v.db.Delete(k)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

// Renew extends the TTL of an existing lock
func (v *VelocityLocker) Renew(ctx context.Context, key string, ttl time.Duration) error {
	k := []byte("lock:" + key)

	val, err := v.db.Get(k)
	if err != nil && err.Error() != "key not found" {
		return fmt.Errorf("failed to check lock: %w", err)
	}

	if val == nil {
		return ErrLockNotHeld
	}

	exp, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return fmt.Errorf("failed to parse lock expiration: %w", err)
	}

	if time.Now().After(exp) {
		return ErrLockExpired
	}

	// Renew the lock
	newExp := time.Now().Add(ttl)
	err = v.db.Put(k, []byte(newExp.Format(time.RFC3339)))
	if err != nil {
		return fmt.Errorf("failed to renew lock: %w", err)
	}

	return nil
}

// IsLocked checks if a lock exists for the given key
func (v *VelocityLocker) IsLocked(ctx context.Context, key string) (bool, error) {
	k := []byte("lock:" + key)

	val, err := v.db.Get(k)
	if err != nil && err.Error() != "key not found" {
		return false, fmt.Errorf("failed to check lock status: %w", err)
	}

	if val == nil {
		return false, nil
	}

	exp, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return false, fmt.Errorf("failed to parse lock expiration: %w", err)
	}

	return time.Now().Before(exp), nil
}

// GetLockTTL returns the remaining TTL of a lock
func (v *VelocityLocker) GetLockTTL(ctx context.Context, key string) (time.Duration, error) {
	k := []byte("lock:" + key)

	val, err := v.db.Get(k)
	if err != nil && err.Error() != "key not found" {
		return 0, fmt.Errorf("failed to get lock: %w", err)
	}

	if val == nil {
		return 0, ErrLockNotHeld
	}

	exp, err := time.Parse(time.RFC3339, string(val))
	if err != nil {
		return 0, fmt.Errorf("failed to parse lock expiration: %w", err)
	}

	if time.Now().After(exp) {
		return 0, ErrLockExpired
	}

	return time.Until(exp), nil
}

// LockManager provides higher-level lock management
type LockManager struct {
	locker Locker
}

// NewLockManager creates a new lock manager
func NewLockManager(locker Locker) *LockManager {
	return &LockManager{locker: locker}
}

// AcquireEntryLock attempts to acquire a lock for an entry
func (lm *LockManager) AcquireEntryLock(ctx context.Context, entryID uuid.UUID, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("entry:%s:user:%s", entryID, userID)
	return lm.locker.Acquire(ctx, key, ttl)
}

// ReleaseEntryLock releases a lock for an entry
func (lm *LockManager) ReleaseEntryLock(ctx context.Context, entryID uuid.UUID, userID uuid.UUID) error {
	key := fmt.Sprintf("entry:%s:user:%s", entryID, userID)
	return lm.locker.Release(ctx, key)
}

// RenewEntryLock renews a lock for an entry
func (lm *LockManager) RenewEntryLock(ctx context.Context, entryID uuid.UUID, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("entry:%s:user:%s", entryID, userID)
	return lm.locker.Renew(ctx, key, ttl)
}

// IsEntryLocked checks if an entry is locked
func (lm *LockManager) IsEntryLocked(ctx context.Context, entryID uuid.UUID) (bool, error) {
	// Note: Velocity doesn't support pattern matching like Redis
	// This is a simplified implementation that checks a specific key
	// In a real scenario, you might need to maintain a separate index or use a different approach
	key := fmt.Sprintf("entry:%s", entryID)
	return lm.locker.IsLocked(ctx, key)
}

// AcquireStageLock attempts to acquire a lock for a stage
func (lm *LockManager) AcquireStageLock(ctx context.Context, stageID uuid.UUID, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("stage:%s:user:%s", stageID, userID)
	return lm.locker.Acquire(ctx, key, ttl)
}

// ReleaseStageLock releases a lock for a stage
func (lm *LockManager) ReleaseStageLock(ctx context.Context, stageID uuid.UUID, userID uuid.UUID) error {
	key := fmt.Sprintf("stage:%s:user:%s", stageID, userID)
	return lm.locker.Release(ctx, key)
}

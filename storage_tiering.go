package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Storage class constants following S3 conventions.
const (
	ClassStandard         = "STANDARD"
	ClassInfrequentAccess = "STANDARD_IA"
	ClassGlacier          = "GLACIER"
	ClassDeepArchive      = "DEEP_ARCHIVE"
)

// validStorageClasses enumerates the recognised classes.
var validStorageClasses = map[string]int{
	ClassStandard:         0,
	ClassInfrequentAccess: 1,
	ClassGlacier:          2,
	ClassDeepArchive:      3,
}

// lifecycleConfigPrefix is the key prefix used to persist per-bucket lifecycle
// configurations inside the DB.
const lifecycleConfigPrefix = "lifecycle:"

// ---------------------------------------------------------------------------
// Lifecycle rule types
// ---------------------------------------------------------------------------

// Transition describes when objects should be moved to a colder storage class.
type Transition struct {
	Days         int    `json:"days"`
	StorageClass string `json:"storage_class"`
}

// Expiration describes when objects should be permanently removed.
type Expiration struct {
	Days                      int  `json:"days,omitempty"`
	ExpiredObjectDeleteMarker bool `json:"expired_object_delete_marker,omitempty"`
}

// NoncurrentVersionExpiration controls removal of noncurrent object versions.
type NoncurrentVersionExpiration struct {
	NoncurrentDays int `json:"noncurrent_days,omitempty"`
}

// LifecycleRuleFilter groups the optional filtering criteria for a rule.
type LifecycleRuleFilter struct {
	Prefix string            `json:"prefix,omitempty"`
	Tags   map[string]string `json:"tags,omitempty"`
}

// LifecycleRule is a single lifecycle rule attached to a bucket.
type LifecycleRule struct {
	ID                          string                       `json:"id"`
	Status                      string                       `json:"status"` // "Enabled" or "Disabled"
	Filter                      LifecycleRuleFilter          `json:"filter"`
	Transitions                 []Transition                 `json:"transitions,omitempty"`
	Expiration                  *Expiration                  `json:"expiration,omitempty"`
	NoncurrentVersionExpiration *NoncurrentVersionExpiration  `json:"noncurrent_version_expiration,omitempty"`
}

// LifecycleConfig holds the full lifecycle configuration for a bucket.
type LifecycleConfig struct {
	Rules []LifecycleRule `json:"rules"`
}

// ---------------------------------------------------------------------------
// Lifecycle status / stats
// ---------------------------------------------------------------------------

// LifecycleStatus exposes cumulative statistics gathered by the background
// worker for introspection and monitoring.
type LifecycleStatus struct {
	LastRun              time.Time `json:"last_run"`
	ObjectsTransitioned  int64     `json:"objects_transitioned"`
	ObjectsExpired       int64     `json:"objects_expired"`
	TransitionErrors     int64     `json:"transition_errors"`
	ExpirationErrors     int64     `json:"expiration_errors"`
	Running              bool      `json:"running"`
	EvaluationInterval   string    `json:"evaluation_interval"`
}

// ---------------------------------------------------------------------------
// StorageTierManager
// ---------------------------------------------------------------------------

// StorageTierManager manages storage class transitions and lifecycle
// evaluation for an object-storage backed by a velocity DB.
type StorageTierManager struct {
	db *DB

	// Background worker state
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
	running  atomic.Bool

	// Stats (updated atomically)
	objectsTransitioned atomic.Int64
	objectsExpired      atomic.Int64
	transitionErrors    atomic.Int64
	expirationErrors    atomic.Int64
	lastRun             atomic.Value // stores time.Time

	mu sync.Mutex // protects cancel / done
}

// NewStorageTierManager creates a new StorageTierManager with the given
// evaluation interval.  If interval is zero the default of 24 hours is used.
func NewStorageTierManager(db *DB, interval time.Duration) *StorageTierManager {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	stm := &StorageTierManager{
		db:       db,
		interval: interval,
	}
	stm.lastRun.Store(time.Time{})
	return stm
}

// ---------------------------------------------------------------------------
// Lifecycle configuration CRUD (per-bucket, stored under "lifecycle:<bucket>")
// ---------------------------------------------------------------------------

// PutBucketLifecycle stores a lifecycle configuration for the given bucket.
// Existing configuration is replaced entirely.
func (stm *StorageTierManager) PutBucketLifecycle(bucket string, config *LifecycleConfig) error {
	if bucket == "" {
		return fmt.Errorf("bucket name is required")
	}
	if config == nil {
		return fmt.Errorf("lifecycle config is required")
	}
	if err := validateLifecycleConfig(config); err != nil {
		return err
	}

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal lifecycle config: %w", err)
	}
	return stm.db.PutWithTTL([]byte(lifecycleConfigPrefix+bucket), data, 0)
}

// GetBucketLifecycle retrieves the lifecycle configuration for the given
// bucket.  Returns nil, nil when no configuration exists.
func (stm *StorageTierManager) GetBucketLifecycle(bucket string) (*LifecycleConfig, error) {
	data, err := stm.db.Get([]byte(lifecycleConfigPrefix + bucket))
	if err != nil {
		return nil, nil // no config stored
	}
	var config LifecycleConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal lifecycle config: %w", err)
	}
	return &config, nil
}

// DeleteBucketLifecycle removes the lifecycle configuration for the given
// bucket.
func (stm *StorageTierManager) DeleteBucketLifecycle(bucket string) error {
	return stm.db.Delete([]byte(lifecycleConfigPrefix + bucket))
}

// ---------------------------------------------------------------------------
// Object transition
// ---------------------------------------------------------------------------

// TransitionObject changes the storage class recorded in an object's metadata.
// The transition is only allowed in a "downward" direction (e.g. STANDARD →
// GLACIER is allowed but not the reverse).
func (stm *StorageTierManager) TransitionObject(path, targetClass string) error {
	if _, ok := validStorageClasses[targetClass]; !ok {
		return fmt.Errorf("invalid storage class: %s", targetClass)
	}

	meta, err := stm.db.GetObjectMetadata(path)
	if err != nil {
		return fmt.Errorf("failed to get object metadata for %s: %w", path, err)
	}

	currentTier := validStorageClasses[meta.StorageClass]
	targetTier := validStorageClasses[targetClass]
	if targetTier <= currentTier {
		return fmt.Errorf("cannot transition from %s to %s: target class must be colder",
			meta.StorageClass, targetClass)
	}

	meta.StorageClass = targetClass
	meta.ModifiedAt = time.Now().UTC()
	return stm.db.saveObjectMetadata(meta)
}

// ---------------------------------------------------------------------------
// Lifecycle evaluation
// ---------------------------------------------------------------------------

// ProcessLifecycle evaluates every enabled rule in the bucket's lifecycle
// configuration against the bucket's objects and applies transitions and
// expirations.  It returns the number of objects transitioned and expired.
func (stm *StorageTierManager) ProcessLifecycle(ctx context.Context, bucket string) (transitioned, expired int, err error) {
	config, err := stm.GetBucketLifecycle(bucket)
	if err != nil {
		return 0, 0, err
	}
	if config == nil || len(config.Rules) == 0 {
		return 0, 0, nil
	}

	// List every object in the bucket.
	objects, err := stm.db.ListObjects(ObjectListOptions{
		Prefix:    bucket + "/",
		Recursive: true,
		MaxKeys:   0, // unlimited – the DB method defaults to 1000
	})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
	}

	now := time.Now().UTC()

	for i := range objects {
		if ctx.Err() != nil {
			return transitioned, expired, ctx.Err()
		}

		obj := &objects[i]
		objectAge := now.Sub(obj.CreatedAt)

		for _, rule := range config.Rules {
			if rule.Status != "Enabled" {
				continue
			}

			if !ruleMatchesObject(rule, obj, bucket) {
				continue
			}

			// --- Transitions ---
			for _, t := range rule.Transitions {
				thresholdDays := time.Duration(t.Days) * 24 * time.Hour
				if objectAge >= thresholdDays {
					// Only transition if the target class is colder than current.
					currentTier := validStorageClasses[obj.StorageClass]
					targetTier := validStorageClasses[t.StorageClass]
					if targetTier > currentTier {
						if terr := stm.TransitionObject(obj.Path, t.StorageClass); terr != nil {
							stm.transitionErrors.Add(1)
							log.Printf("lifecycle: transition error for %s: %v", obj.Path, terr)
						} else {
							transitioned++
							stm.objectsTransitioned.Add(1)
							obj.StorageClass = t.StorageClass // reflect locally
						}
					}
				}
			}

			// --- Expiration ---
			if rule.Expiration != nil && rule.Expiration.Days > 0 {
				thresholdDays := time.Duration(rule.Expiration.Days) * 24 * time.Hour
				if objectAge >= thresholdDays {
					if derr := stm.db.DeleteObjectInternal(obj.Path, "lifecycle"); derr != nil {
						stm.expirationErrors.Add(1)
						log.Printf("lifecycle: expiration error for %s: %v", obj.Path, derr)
					} else {
						expired++
						stm.objectsExpired.Add(1)
						break // object deleted, no more rules apply
					}
				}
			}
		}
	}

	return transitioned, expired, nil
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

// Start begins the background lifecycle evaluation goroutine. It evaluates
// all buckets that have a lifecycle configuration on the configured interval.
// Calling Start on an already-running manager is a no-op.
func (stm *StorageTierManager) Start(ctx context.Context) {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	if stm.running.Load() {
		return
	}

	childCtx, cancel := context.WithCancel(ctx)
	stm.cancel = cancel
	stm.done = make(chan struct{})
	stm.running.Store(true)

	go stm.runLoop(childCtx)
}

// Stop signals the background worker to stop and waits for it to finish.
// Calling Stop on a manager that is not running is a no-op.
func (stm *StorageTierManager) Stop() {
	stm.mu.Lock()
	cancel := stm.cancel
	done := stm.done
	stm.mu.Unlock()

	if cancel == nil || !stm.running.Load() {
		return
	}

	cancel()
	<-done
}

// runLoop is the background goroutine.  It runs one full evaluation
// immediately, then once per interval.
func (stm *StorageTierManager) runLoop(ctx context.Context) {
	defer func() {
		stm.running.Store(false)
		close(stm.done)
	}()

	// Run immediately on start.
	stm.evaluateAll(ctx)

	ticker := time.NewTicker(stm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stm.evaluateAll(ctx)
		}
	}
}

// evaluateAll discovers every bucket with a lifecycle config and calls
// ProcessLifecycle for each.
func (stm *StorageTierManager) evaluateAll(ctx context.Context) {
	buckets, err := stm.listBucketsWithLifecycle()
	if err != nil {
		log.Printf("lifecycle: failed to enumerate buckets: %v", err)
		return
	}

	for _, bucket := range buckets {
		if ctx.Err() != nil {
			return
		}
		trans, exp, err := stm.ProcessLifecycle(ctx, bucket)
		if err != nil {
			log.Printf("lifecycle: error processing bucket %s: %v", bucket, err)
		} else if trans > 0 || exp > 0 {
			log.Printf("lifecycle: bucket %s – transitioned %d, expired %d", bucket, trans, exp)
		}
	}

	stm.lastRun.Store(time.Now().UTC())
}

// listBucketsWithLifecycle returns the names of buckets that have a stored
// lifecycle configuration.
func (stm *StorageTierManager) listBucketsWithLifecycle() ([]string, error) {
	keys, err := stm.db.Keys(lifecycleConfigPrefix + "*")
	if err != nil {
		return nil, err
	}

	buckets := make([]string, 0, len(keys))
	for _, key := range keys {
		bucket := strings.TrimPrefix(key, lifecycleConfigPrefix)
		if bucket != "" {
			buckets = append(buckets, bucket)
		}
	}
	return buckets, nil
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// GetLifecycleStatus returns a snapshot of the manager's cumulative statistics.
func (stm *StorageTierManager) GetLifecycleStatus() LifecycleStatus {
	var last time.Time
	if v := stm.lastRun.Load(); v != nil {
		last = v.(time.Time)
	}
	return LifecycleStatus{
		LastRun:             last,
		ObjectsTransitioned: stm.objectsTransitioned.Load(),
		ObjectsExpired:      stm.objectsExpired.Load(),
		TransitionErrors:    stm.transitionErrors.Load(),
		ExpirationErrors:    stm.expirationErrors.Load(),
		Running:             stm.running.Load(),
		EvaluationInterval:  stm.interval.String(),
	}
}

// ResetStats zeroes out the cumulative counters. Useful after draining metrics.
func (stm *StorageTierManager) ResetStats() {
	stm.objectsTransitioned.Store(0)
	stm.objectsExpired.Store(0)
	stm.transitionErrors.Store(0)
	stm.expirationErrors.Store(0)
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

// validateLifecycleConfig performs basic sanity checks on a lifecycle config.
func validateLifecycleConfig(config *LifecycleConfig) error {
	ids := make(map[string]struct{}, len(config.Rules))
	for i, rule := range config.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule at index %d must have an ID", i)
		}
		if _, dup := ids[rule.ID]; dup {
			return fmt.Errorf("duplicate rule ID: %s", rule.ID)
		}
		ids[rule.ID] = struct{}{}

		if rule.Status != "Enabled" && rule.Status != "Disabled" {
			return fmt.Errorf("rule %s: status must be 'Enabled' or 'Disabled'", rule.ID)
		}

		for j, t := range rule.Transitions {
			if _, ok := validStorageClasses[t.StorageClass]; !ok {
				return fmt.Errorf("rule %s: transition %d: invalid storage class %s",
					rule.ID, j, t.StorageClass)
			}
			if t.Days < 0 {
				return fmt.Errorf("rule %s: transition %d: days must be non-negative", rule.ID, j)
			}
		}

		// Verify transitions are ordered by tier depth (e.g. IA before Glacier).
		for j := 1; j < len(rule.Transitions); j++ {
			prevTier := validStorageClasses[rule.Transitions[j-1].StorageClass]
			curTier := validStorageClasses[rule.Transitions[j].StorageClass]
			if curTier <= prevTier {
				return fmt.Errorf("rule %s: transitions must move to progressively colder classes", rule.ID)
			}
			if rule.Transitions[j].Days <= rule.Transitions[j-1].Days {
				return fmt.Errorf("rule %s: transition days must be increasing", rule.ID)
			}
		}

		if rule.Expiration != nil && rule.Expiration.Days < 0 {
			return fmt.Errorf("rule %s: expiration days must be non-negative", rule.ID)
		}

		if rule.NoncurrentVersionExpiration != nil && rule.NoncurrentVersionExpiration.NoncurrentDays < 0 {
			return fmt.Errorf("rule %s: noncurrent version expiration days must be non-negative", rule.ID)
		}
	}
	return nil
}

// ruleMatchesObject checks whether a lifecycle rule's filter matches an object.
func ruleMatchesObject(rule LifecycleRule, obj *ObjectMetadata, bucket string) bool {
	// Strip the bucket prefix to get the key relative to the bucket.
	key := strings.TrimPrefix(obj.Path, bucket+"/")

	// Prefix filter.
	if rule.Filter.Prefix != "" && !strings.HasPrefix(key, rule.Filter.Prefix) {
		return false
	}

	// Tags filter: every tag in the filter must be present on the object with
	// the same value.
	if len(rule.Filter.Tags) > 0 {
		if obj.Tags == nil {
			return false
		}
		for k, v := range rule.Filter.Tags {
			if obj.Tags[k] != v {
				return false
			}
		}
	}

	return true
}

// IsValidStorageClass reports whether class is a recognised storage class.
func IsValidStorageClass(class string) bool {
	_, ok := validStorageClasses[class]
	return ok
}

// StorageClassTier returns the numeric tier for a storage class (lower = hotter).
// Returns -1 for unknown classes.
func StorageClassTier(class string) int {
	if tier, ok := validStorageClasses[class]; ok {
		return tier
	}
	return -1
}

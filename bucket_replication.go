package velocity

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	bucketReplPrefix       = "bucket:repl:"
	bucketReplStatusPrefix = "bucket:repl:status:"
)

// ReplicationRuleStatus represents whether a rule is active
type ReplicationRuleStatus string

const (
	ReplicationRuleEnabled  ReplicationRuleStatus = "Enabled"
	ReplicationRuleDisabled ReplicationRuleStatus = "Disabled"
)

// ReplicationStatus tracks the replication state of an individual object
type ReplicationStatus string

const (
	ReplicationStatusPending   ReplicationStatus = "PENDING"
	ReplicationStatusComplete  ReplicationStatus = "COMPLETE"
	ReplicationStatusFailed    ReplicationStatus = "FAILED"
	ReplicationStatusReplica   ReplicationStatus = "REPLICA"
	ReplicationStatusNone      ReplicationStatus = ""
)

// ReplicationRule defines a single bucket-level replication rule
type ReplicationRule struct {
	ID                string                `json:"id"`
	Status            ReplicationRuleStatus `json:"status"`
	Priority          int                   `json:"priority"`
	SourceBucket      string                `json:"source_bucket"`
	DestinationBucket string                `json:"destination_bucket"`
	Prefix            string                `json:"prefix,omitempty"`
	TagFilter         map[string]string     `json:"tag_filter,omitempty"`
	StorageClassOverride string             `json:"storage_class_override,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	ModifiedAt        time.Time             `json:"modified_at"`
}

// BucketReplicationConfig holds all replication rules for a source bucket
type BucketReplicationConfig struct {
	SourceBucket string            `json:"source_bucket"`
	Rules        []ReplicationRule `json:"rules"`
}

// ObjectReplicationStatus records the replication state of an object per rule
type ObjectReplicationStatus struct {
	ObjectPath   string                       `json:"object_path"`
	RuleStatuses map[string]RuleObjectStatus  `json:"rule_statuses"` // rule ID -> status
}

// RuleObjectStatus is the per-rule replication outcome for one object
type RuleObjectStatus struct {
	RuleID            string            `json:"rule_id"`
	Status            ReplicationStatus `json:"status"`
	DestinationBucket string            `json:"destination_bucket"`
	ReplicatedAt      time.Time         `json:"replicated_at,omitempty"`
	ErrorMessage      string            `json:"error_message,omitempty"`
}

// BucketReplicationManager manages bucket-level replication rules
type BucketReplicationManager struct {
	db *DB
	mu sync.RWMutex
}

// NewBucketReplicationManager creates a new bucket replication manager
func NewBucketReplicationManager(db *DB) *BucketReplicationManager {
	return &BucketReplicationManager{db: db}
}

// -------------------------------------------------------------------
// CRUD for replication configurations
// -------------------------------------------------------------------

// PutReplicationConfig stores the full replication configuration for a bucket.
// It validates that every rule references the correct source bucket, that rule
// IDs are unique, and that destination buckets exist.
func (brm *BucketReplicationManager) PutReplicationConfig(config *BucketReplicationConfig) error {
	if config == nil {
		return fmt.Errorf("replication config cannot be nil")
	}
	if config.SourceBucket == "" {
		return fmt.Errorf("source bucket is required")
	}

	// Verify source bucket exists
	if !brm.db.Has([]byte(bucketMetaPrefix + config.SourceBucket)) {
		return fmt.Errorf("NoSuchBucket: source bucket %q does not exist", config.SourceBucket)
	}

	seenIDs := make(map[string]struct{}, len(config.Rules))
	now := time.Now().UTC()

	for i := range config.Rules {
		rule := &config.Rules[i]

		// Auto-generate ID when missing
		if rule.ID == "" {
			rule.ID = generateObjectID()
		}
		if _, dup := seenIDs[rule.ID]; dup {
			return fmt.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}

		// Default status
		if rule.Status == "" {
			rule.Status = ReplicationRuleEnabled
		}
		if rule.Status != ReplicationRuleEnabled && rule.Status != ReplicationRuleDisabled {
			return fmt.Errorf("invalid rule status %q; must be Enabled or Disabled", rule.Status)
		}

		// Source must match the config-level bucket
		if rule.SourceBucket == "" {
			rule.SourceBucket = config.SourceBucket
		}
		if rule.SourceBucket != config.SourceBucket {
			return fmt.Errorf("rule %s source bucket %q does not match config source %q",
				rule.ID, rule.SourceBucket, config.SourceBucket)
		}

		if rule.DestinationBucket == "" {
			return fmt.Errorf("rule %s: destination bucket is required", rule.ID)
		}
		if rule.SourceBucket == rule.DestinationBucket {
			return fmt.Errorf("rule %s: source and destination bucket cannot be the same", rule.ID)
		}

		// Verify destination bucket exists
		if !brm.db.Has([]byte(bucketMetaPrefix + rule.DestinationBucket)) {
			return fmt.Errorf("NoSuchBucket: destination bucket %q does not exist", rule.DestinationBucket)
		}

		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = now
		}
		rule.ModifiedAt = now
	}

	brm.mu.Lock()
	defer brm.mu.Unlock()

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal replication config: %w", err)
	}

	return brm.db.PutWithTTL([]byte(bucketReplPrefix+config.SourceBucket), data, 0)
}

// GetReplicationConfig retrieves the replication configuration for a bucket
func (brm *BucketReplicationManager) GetReplicationConfig(bucket string) (*BucketReplicationConfig, error) {
	brm.mu.RLock()
	defer brm.mu.RUnlock()

	data, err := brm.db.Get([]byte(bucketReplPrefix + bucket))
	if err != nil {
		return nil, fmt.Errorf("ReplicationConfigurationNotFoundError: no replication config for bucket %q", bucket)
	}

	var config BucketReplicationConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal replication config: %w", err)
	}
	return &config, nil
}

// DeleteReplicationConfig removes the replication configuration for a bucket
func (brm *BucketReplicationManager) DeleteReplicationConfig(bucket string) error {
	brm.mu.Lock()
	defer brm.mu.Unlock()

	if !brm.db.Has([]byte(bucketReplPrefix + bucket)) {
		return fmt.Errorf("ReplicationConfigurationNotFoundError: no replication config for bucket %q", bucket)
	}

	return brm.db.Delete([]byte(bucketReplPrefix + bucket))
}

// -------------------------------------------------------------------
// Rule-level helpers
// -------------------------------------------------------------------

// GetRule returns a single rule by ID from a bucket's replication config
func (brm *BucketReplicationManager) GetRule(bucket, ruleID string) (*ReplicationRule, error) {
	config, err := brm.GetReplicationConfig(bucket)
	if err != nil {
		return nil, err
	}
	for i := range config.Rules {
		if config.Rules[i].ID == ruleID {
			return &config.Rules[i], nil
		}
	}
	return nil, fmt.Errorf("rule %q not found in bucket %q", ruleID, bucket)
}

// AddRule appends a single rule to an existing config (or creates one)
func (brm *BucketReplicationManager) AddRule(bucket string, rule ReplicationRule) error {
	config, err := brm.GetReplicationConfig(bucket)
	if err != nil {
		// No config yet – create a fresh one
		config = &BucketReplicationConfig{
			SourceBucket: bucket,
		}
	}
	config.Rules = append(config.Rules, rule)
	return brm.PutReplicationConfig(config)
}

// RemoveRule removes a single rule by ID and persists the config
func (brm *BucketReplicationManager) RemoveRule(bucket, ruleID string) error {
	config, err := brm.GetReplicationConfig(bucket)
	if err != nil {
		return err
	}
	found := false
	rules := make([]ReplicationRule, 0, len(config.Rules))
	for _, r := range config.Rules {
		if r.ID == ruleID {
			found = true
			continue
		}
		rules = append(rules, r)
	}
	if !found {
		return fmt.Errorf("rule %q not found in bucket %q", ruleID, bucket)
	}
	config.Rules = rules
	// If no rules left, delete the whole config
	if len(config.Rules) == 0 {
		return brm.DeleteReplicationConfig(bucket)
	}
	return brm.PutReplicationConfig(config)
}

// -------------------------------------------------------------------
// Filtering
// -------------------------------------------------------------------

// FilterObjects checks whether an object (identified by its key and metadata)
// matches the filters of a given rule. Returns true when the object should be
// replicated by this rule.
func (brm *BucketReplicationManager) FilterObjects(rule *ReplicationRule, objectKey string, meta *ObjectMetadata) bool {
	if rule == nil || meta == nil {
		return false
	}

	// Prefix filter
	if rule.Prefix != "" {
		// The objectKey may or may not include the bucket prefix; strip it
		// so we match against the key relative to the bucket root.
		key := stripBucketPrefix(objectKey, rule.SourceBucket)
		if !strings.HasPrefix(key, rule.Prefix) {
			return false
		}
	}

	// Tag filter – every tag in the rule must be present with the same value
	if len(rule.TagFilter) > 0 {
		if meta.Tags == nil {
			return false
		}
		for k, v := range rule.TagFilter {
			if meta.Tags[k] != v {
				return false
			}
		}
	}

	return true
}

// matchingRules returns every enabled rule that matches the given object.
// Rules are returned sorted by priority (lower number = higher priority).
func (brm *BucketReplicationManager) matchingRules(config *BucketReplicationConfig, objectKey string, meta *ObjectMetadata) []ReplicationRule {
	var matched []ReplicationRule
	for _, rule := range config.Rules {
		if rule.Status != ReplicationRuleEnabled {
			continue
		}
		if brm.FilterObjects(&rule, objectKey, meta) {
			matched = append(matched, rule)
		}
	}

	// Stable sort by priority ascending
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0 && matched[j].Priority < matched[j-1].Priority; j-- {
			matched[j], matched[j-1] = matched[j-1], matched[j]
		}
	}
	return matched
}

// -------------------------------------------------------------------
// Replication processing
// -------------------------------------------------------------------

// ProcessReplication evaluates all enabled rules for the source bucket and
// replicates the object to every matching destination bucket. It stores the
// object in the destination using the same key (relative to the bucket root),
// optionally overriding the storage class.
//
// It returns the aggregated replication status across all rules.
func (brm *BucketReplicationManager) ProcessReplication(bucket, key string, data []byte, meta *ObjectMetadata) (*ObjectReplicationStatus, error) {
	if meta == nil {
		return nil, fmt.Errorf("object metadata is required")
	}

	config, err := brm.GetReplicationConfig(bucket)
	if err != nil {
		// No replication config – nothing to do
		return nil, nil
	}

	matched := brm.matchingRules(config, key, meta)
	if len(matched) == 0 {
		return nil, nil
	}

	// Build path relative to the source bucket
	relativeKey := stripBucketPrefix(key, bucket)

	status := &ObjectReplicationStatus{
		ObjectPath:   bucket + "/" + relativeKey,
		RuleStatuses: make(map[string]RuleObjectStatus, len(matched)),
	}

	// Track which destination buckets we already replicated to so we don't
	// duplicate work when multiple rules point to the same destination.
	replicated := make(map[string]struct{})

	for _, rule := range matched {
		rs := RuleObjectStatus{
			RuleID:            rule.ID,
			DestinationBucket: rule.DestinationBucket,
			Status:            ReplicationStatusPending,
		}

		if _, done := replicated[rule.DestinationBucket]; done {
			rs.Status = ReplicationStatusComplete
			rs.ReplicatedAt = time.Now().UTC()
			status.RuleStatuses[rule.ID] = rs
			continue
		}

		destPath := rule.DestinationBucket + "/" + relativeKey

		storageClass := meta.StorageClass
		if rule.StorageClassOverride != "" {
			storageClass = rule.StorageClassOverride
		}

		opts := &ObjectOptions{
			Version:         meta.Version,
			Tags:            copyTags(meta.Tags),
			CustomMetadata:  copyTags(meta.CustomMetadata),
			Encrypt:         meta.Encrypted,
			StorageClass:    storageClass,
			SystemOperation: true,
		}

		_, storeErr := brm.db.StoreObject(destPath, meta.ContentType, "bucket-replication", data, opts)
		if storeErr != nil {
			rs.Status = ReplicationStatusFailed
			rs.ErrorMessage = storeErr.Error()
		} else {
			rs.Status = ReplicationStatusComplete
			rs.ReplicatedAt = time.Now().UTC()
			replicated[rule.DestinationBucket] = struct{}{}
		}

		status.RuleStatuses[rule.ID] = rs
	}

	// Persist the per-object replication status
	if err := brm.setObjectReplicationStatus(status); err != nil {
		return status, fmt.Errorf("replication succeeded but failed to persist status: %w", err)
	}

	return status, brm.aggregateError(status)
}

// -------------------------------------------------------------------
// Replication status tracking
// -------------------------------------------------------------------

// setObjectReplicationStatus persists the replication status for an object
func (brm *BucketReplicationManager) setObjectReplicationStatus(status *ObjectReplicationStatus) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	key := bucketReplStatusPrefix + status.ObjectPath
	return brm.db.PutWithTTL([]byte(key), data, 0)
}

// GetObjectReplicationStatus returns the replication status for an object
func (brm *BucketReplicationManager) GetObjectReplicationStatus(objectPath string) (*ObjectReplicationStatus, error) {
	data, err := brm.db.Get([]byte(bucketReplStatusPrefix + objectPath))
	if err != nil {
		return nil, fmt.Errorf("no replication status for %q", objectPath)
	}
	var status ObjectReplicationStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetAggregateStatus returns a single ReplicationStatus that summarises every
// rule's outcome for the object. FAILED if any rule failed; PENDING if any
// rule is pending; COMPLETE if all succeeded.
func (brm *BucketReplicationManager) GetAggregateStatus(objectPath string) (ReplicationStatus, error) {
	status, err := brm.GetObjectReplicationStatus(objectPath)
	if err != nil {
		return ReplicationStatusNone, err
	}
	return computeAggregate(status), nil
}

// -------------------------------------------------------------------
// Listing helpers
// -------------------------------------------------------------------

// ListReplicationConfigs returns all bucket replication configurations
func (brm *BucketReplicationManager) ListReplicationConfigs() ([]BucketReplicationConfig, error) {
	brm.mu.RLock()
	defer brm.mu.RUnlock()

	keys, err := brm.db.Keys(bucketReplPrefix + "*")
	if err != nil {
		return nil, err
	}

	var configs []BucketReplicationConfig
	for _, k := range keys {
		// Skip status keys
		if strings.HasPrefix(k, bucketReplStatusPrefix) {
			continue
		}
		data, err := brm.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var config BucketReplicationConfig
		if err := json.Unmarshal(data, &config); err != nil {
			continue
		}
		configs = append(configs, config)
	}
	return configs, nil
}

// ListPendingReplications returns object paths that still have PENDING status
// for the given bucket.
func (brm *BucketReplicationManager) ListPendingReplications(bucket string) ([]ObjectReplicationStatus, error) {
	prefix := bucketReplStatusPrefix + bucket + "/"
	keys, err := brm.db.Keys(prefix + "*")
	if err != nil {
		return nil, err
	}

	var pending []ObjectReplicationStatus
	for _, k := range keys {
		data, err := brm.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var status ObjectReplicationStatus
		if err := json.Unmarshal(data, &status); err != nil {
			continue
		}
		if computeAggregate(&status) == ReplicationStatusPending {
			pending = append(pending, status)
		}
	}
	return pending, nil
}

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

// aggregateError returns a non-nil error if any rule failed
func (brm *BucketReplicationManager) aggregateError(status *ObjectReplicationStatus) error {
	var failures []string
	for _, rs := range status.RuleStatuses {
		if rs.Status == ReplicationStatusFailed {
			failures = append(failures, fmt.Sprintf("rule %s -> %s: %s",
				rs.RuleID, rs.DestinationBucket, rs.ErrorMessage))
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("replication partially failed: %s", strings.Join(failures, "; "))
}

// computeAggregate derives an overall status from per-rule statuses.
func computeAggregate(status *ObjectReplicationStatus) ReplicationStatus {
	if len(status.RuleStatuses) == 0 {
		return ReplicationStatusNone
	}
	hasPending := false
	for _, rs := range status.RuleStatuses {
		if rs.Status == ReplicationStatusFailed {
			return ReplicationStatusFailed
		}
		if rs.Status == ReplicationStatusPending {
			hasPending = true
		}
	}
	if hasPending {
		return ReplicationStatusPending
	}
	return ReplicationStatusComplete
}

// stripBucketPrefix removes a leading "bucket/" from an object key when present.
func stripBucketPrefix(key, bucket string) string {
	prefix := bucket + "/"
	if strings.HasPrefix(key, prefix) {
		return strings.TrimPrefix(key, prefix)
	}
	return key
}

// copyTags returns a shallow copy of a string map (nil-safe).
func copyTags(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

package s3

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// VersioningState represents the versioning state of a bucket
type VersioningState string

const (
	// VersioningUnset means versioning has never been configured
	VersioningUnset VersioningState = ""
	// VersioningEnabled means versioning is active
	VersioningEnabled VersioningState = "Enabled"
	// VersioningSuspended means versioning is paused
	VersioningSuspended VersioningState = "Suspended"
)

const bucketVersioningPrefix = "bucket:versioning:"

// BucketVersioning manages per-bucket versioning state
type BucketVersioning struct {
	store KVStore
}

// NewBucketVersioning creates a new bucket versioning manager
func NewBucketVersioning(store KVStore) *BucketVersioning {
	return &BucketVersioning{store: store}
}

// SetVersioning sets the versioning state for a bucket
func (bv *BucketVersioning) SetVersioning(bucket string, state VersioningState) error {
	if state != VersioningEnabled && state != VersioningSuspended && state != VersioningUnset {
		return fmt.Errorf("invalid versioning state: %s", state)
	}

	data := map[string]string{"status": string(state)}
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return bv.store.PutWithTTL([]byte(bucketVersioningPrefix+bucket), encoded, 0)
}

// GetVersioning gets the versioning state for a bucket
func (bv *BucketVersioning) GetVersioning(bucket string) (VersioningState, error) {
	data, err := bv.store.Get([]byte(bucketVersioningPrefix + bucket))
	if err != nil {
		return VersioningUnset, nil // Default: unset
	}

	var state map[string]string
	if err := json.Unmarshal(data, &state); err != nil {
		return VersioningUnset, err
	}

	return VersioningState(state["status"]), nil
}

func generateVersionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("v%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("v%x", b[:])
}

// IsVersioningEnabled checks if versioning is enabled for a bucket
func (bv *BucketVersioning) IsVersioningEnabled(bucket string) bool {
	state, err := bv.GetVersioning(bucket)
	if err != nil {
		return false
	}
	return state == VersioningEnabled
}

// ShouldCreateVersion determines if a new version should be created for an object
// Returns: (createVersion bool, versionID string)
func (bv *BucketVersioning) ShouldCreateVersion(bucket string) (bool, string) {
	state, err := bv.GetVersioning(bucket)
	if err != nil {
		return false, "null"
	}

	switch state {
	case VersioningEnabled:
		return true, generateVersionID()
	case VersioningSuspended:
		return false, "null"
	default:
		return false, generateVersionID()
	}
}

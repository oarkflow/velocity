package velocity

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	bucketMetaPrefix   = "bucket:meta:"
	bucketConfigPrefix = "bucket:config:"
	bucketPolicyPrefix = "bucket:policy:"
	bucketQuotaPrefix  = "bucket:quota:"
)

// BucketInfo represents bucket metadata
type BucketInfo struct {
	Name           string            `json:"name" xml:"Name"`
	CreationDate   time.Time         `json:"creation_date" xml:"CreationDate"`
	Owner          string            `json:"owner"`
	Region         string            `json:"region"`
	ObjectLockEnabled bool           `json:"object_lock_enabled"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// BucketConfig holds per-bucket configuration
type BucketConfig struct {
	Versioning       string            `json:"versioning"`        // "", "Enabled", "Suspended"
	DefaultEncryption *BucketEncryption `json:"default_encryption,omitempty"`
	Logging          *BucketLogging    `json:"logging,omitempty"`
}

// BucketEncryption represents default encryption settings
type BucketEncryption struct {
	SSEAlgorithm string `json:"sse_algorithm"` // "AES256" or "aws:kms"
	KMSKeyID     string `json:"kms_key_id,omitempty"`
}

// BucketLogging represents logging configuration
type BucketLogging struct {
	Enabled      bool   `json:"enabled"`
	TargetBucket string `json:"target_bucket"`
	TargetPrefix string `json:"target_prefix"`
}

// BucketQuota represents storage quota
type BucketQuota struct {
	MaxSizeBytes  int64 `json:"max_size_bytes"`
	MaxObjects    int64 `json:"max_objects"`
	CurrentSize   int64 `json:"current_size"`
	CurrentObjects int64 `json:"current_objects"`
}

// BucketManager manages bucket operations
type BucketManager struct {
	db *DB
}

// NewBucketManager creates a new bucket manager
func NewBucketManager(db *DB) *BucketManager {
	return &BucketManager{db: db}
}

var bucketNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// ValidateBucketName checks if a bucket name meets S3 naming rules
func ValidateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf("bucket name must be between 3 and 63 characters")
	}
	if !bucketNameRegex.MatchString(name) {
		return fmt.Errorf("invalid bucket name: must be lowercase alphanumeric with hyphens and dots")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("bucket name cannot contain consecutive dots")
	}
	if strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return fmt.Errorf("bucket name cannot contain adjacent dot and hyphen")
	}
	// Check for IP address format
	parts := strings.Split(name, ".")
	if len(parts) == 4 {
		allDigits := true
		for _, p := range parts {
			for _, c := range p {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
		}
		if allDigits {
			return fmt.Errorf("bucket name cannot be formatted as an IP address")
		}
	}
	return nil
}

// CreateBucket creates a new bucket
func (bm *BucketManager) CreateBucket(name, owner, region string) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}

	// Check if bucket exists
	if bm.db.Has([]byte(bucketMetaPrefix + name)) {
		return fmt.Errorf("BucketAlreadyExists")
	}

	info := &BucketInfo{
		Name:         name,
		CreationDate: time.Now().UTC(),
		Owner:        owner,
		Region:       region,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	if err := bm.db.PutWithTTL([]byte(bucketMetaPrefix+name), data, 0); err != nil {
		return err
	}

	// Create default config
	config := &BucketConfig{
		Versioning: "",
	}
	configData, err := json.Marshal(config)
	if err != nil {
		return err
	}

	return bm.db.PutWithTTL([]byte(bucketConfigPrefix+name), configData, 0)
}

// DeleteBucket deletes a bucket (must be empty)
func (bm *BucketManager) DeleteBucket(name string) error {
	if !bm.db.Has([]byte(bucketMetaPrefix + name)) {
		return fmt.Errorf("NoSuchBucket")
	}

	// Check if bucket is empty
	objects, err := bm.db.ListObjects(ObjectListOptions{
		Prefix:  name + "/",
		MaxKeys: 1,
	})
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		return fmt.Errorf("BucketNotEmpty")
	}

	// Delete metadata, config, policy, quota
	bm.db.Delete([]byte(bucketMetaPrefix + name))
	bm.db.Delete([]byte(bucketConfigPrefix + name))
	bm.db.Delete([]byte(bucketPolicyPrefix + name))
	bm.db.Delete([]byte(bucketQuotaPrefix + name))

	return nil
}

// HeadBucket checks if a bucket exists
func (bm *BucketManager) HeadBucket(name string) (*BucketInfo, error) {
	data, err := bm.db.Get([]byte(bucketMetaPrefix + name))
	if err != nil {
		return nil, fmt.Errorf("NoSuchBucket")
	}

	var info BucketInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// ListBuckets lists all buckets optionally filtered by owner
func (bm *BucketManager) ListBuckets(owner string) ([]BucketInfo, error) {
	keys, err := bm.db.Keys(bucketMetaPrefix + "*")
	if err != nil {
		return nil, err
	}

	var buckets []BucketInfo
	for _, key := range keys {
		data, err := bm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var info BucketInfo
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}

		if owner == "" || info.Owner == owner {
			buckets = append(buckets, info)
		}
	}

	return buckets, nil
}

// GetBucketConfig retrieves bucket configuration
func (bm *BucketManager) GetBucketConfig(name string) (*BucketConfig, error) {
	data, err := bm.db.Get([]byte(bucketConfigPrefix + name))
	if err != nil {
		return &BucketConfig{}, nil
	}

	var config BucketConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SetBucketConfig updates bucket configuration
func (bm *BucketManager) SetBucketConfig(name string, config *BucketConfig) error {
	if !bm.db.Has([]byte(bucketMetaPrefix + name)) {
		return fmt.Errorf("NoSuchBucket")
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	return bm.db.PutWithTTL([]byte(bucketConfigPrefix+name), data, 0)
}

// SetBucketVersioning sets the versioning state for a bucket
func (bm *BucketManager) SetBucketVersioning(name, state string) error {
	config, err := bm.GetBucketConfig(name)
	if err != nil {
		return err
	}

	if state != "" && state != "Enabled" && state != "Suspended" {
		return fmt.Errorf("invalid versioning state: %s", state)
	}

	config.Versioning = state
	return bm.SetBucketConfig(name, config)
}

// GetBucketVersioning gets the versioning state
func (bm *BucketManager) GetBucketVersioning(name string) (string, error) {
	config, err := bm.GetBucketConfig(name)
	if err != nil {
		return "", err
	}
	return config.Versioning, nil
}

// SetBucketPolicy sets bucket policy
func (bm *BucketManager) SetBucketPolicy(name string, policy json.RawMessage) error {
	if !bm.db.Has([]byte(bucketMetaPrefix + name)) {
		return fmt.Errorf("NoSuchBucket")
	}
	return bm.db.PutWithTTL([]byte(bucketPolicyPrefix+name), policy, 0)
}

// GetBucketPolicy retrieves bucket policy
func (bm *BucketManager) GetBucketPolicy(name string) (json.RawMessage, error) {
	data, err := bm.db.Get([]byte(bucketPolicyPrefix + name))
	if err != nil {
		return nil, fmt.Errorf("NoSuchBucketPolicy")
	}
	return data, nil
}

// DeleteBucketPolicy deletes bucket policy
func (bm *BucketManager) DeleteBucketPolicy(name string) error {
	return bm.db.Delete([]byte(bucketPolicyPrefix + name))
}

// SetBucketQuota sets storage quota for a bucket
func (bm *BucketManager) SetBucketQuota(name string, quota *BucketQuota) error {
	data, err := json.Marshal(quota)
	if err != nil {
		return err
	}
	return bm.db.PutWithTTL([]byte(bucketQuotaPrefix+name), data, 0)
}

// GetBucketQuota retrieves bucket quota
func (bm *BucketManager) GetBucketQuota(name string) (*BucketQuota, error) {
	data, err := bm.db.Get([]byte(bucketQuotaPrefix + name))
	if err != nil {
		return nil, nil // No quota set
	}

	var quota BucketQuota
	if err := json.Unmarshal(data, &quota); err != nil {
		return nil, err
	}

	return &quota, nil
}

// SetBucketEncryption sets default encryption
func (bm *BucketManager) SetBucketEncryption(name string, enc *BucketEncryption) error {
	config, err := bm.GetBucketConfig(name)
	if err != nil {
		return err
	}

	config.DefaultEncryption = enc
	return bm.SetBucketConfig(name, config)
}

// GetBucketEncryption gets default encryption
func (bm *BucketManager) GetBucketEncryption(name string) (*BucketEncryption, error) {
	config, err := bm.GetBucketConfig(name)
	if err != nil {
		return nil, err
	}
	return config.DefaultEncryption, nil
}

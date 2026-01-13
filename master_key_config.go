package velocity

import (
	"time"
)

// MasterKeyConfig defines how master keys are managed
type MasterKeyConfig struct {
	// Source determines where the master key comes from
	Source MasterKeySource `json:"source"`
	
	// UserKeyCache settings for user-defined keys
	UserKeyCache UserKeyCacheConfig `json:"user_key_cache"`
	
	// ShamirConfig for secret sharing persistence
	ShamirConfig ShamirSecretConfig `json:"shamir_config"`
}

// MasterKeySource defines the source of the master key
type MasterKeySource string

const (
	// SystemFile uses the traditional master.key file approach
	SystemFile MasterKeySource = "system_file"
	
	// UserDefined prompts user for key on each operation
	UserDefined MasterKeySource = "user_defined"
	
	// ShamirShared uses Shamir secret sharing for key reconstruction
	ShamirShared MasterKeySource = "shamir_shared"
)

// UserKeyCacheConfig controls caching of user-defined keys
type UserKeyCacheConfig struct {
	// Enabled determines if user keys should be cached
	Enabled bool `json:"enabled"`
	
	// TTL is how long to cache the user key
	TTL time.Duration `json:"ttl"`
	
	// MaxIdleTime clears cache if no operations for this duration
	MaxIdleTime time.Duration `json:"max_idle_time"`
}

// ShamirSecretConfig controls Shamir secret sharing
type ShamirSecretConfig struct {
	// Enabled determines if Shamir sharing is used
	Enabled bool `json:"enabled"`
	
	// Threshold is minimum shares needed to reconstruct key
	Threshold int `json:"threshold"`
	
	// TotalShares is total number of shares to generate
	TotalShares int `json:"total_shares"`
	
	// SharesPath is directory to store share files
	SharesPath string `json:"shares_path"`
}

// DefaultMasterKeyConfig returns sensible defaults
func DefaultMasterKeyConfig() MasterKeyConfig {
	return MasterKeyConfig{
		Source: SystemFile,
		UserKeyCache: UserKeyCacheConfig{
			Enabled:     true,
			TTL:         30 * time.Minute,
			MaxIdleTime: 10 * time.Minute,
		},
		ShamirConfig: ShamirSecretConfig{
			Enabled:     false,
			Threshold:   3,
			TotalShares: 5,
			SharesPath:  "./shamir_shares",
		},
	}
}
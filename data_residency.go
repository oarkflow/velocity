package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// DataResidencyPolicy enforces geographic residency rules.
type DataResidencyPolicy struct {
	PolicyID   string   `json:"policy_id"`
	PathPrefix string   `json:"path_prefix"`
	Regions    []string `json:"regions"` // Allowed regions (ISO country/region codes)
	Framework  string   `json:"framework"`
	Enabled    bool     `json:"enabled"`
}

// DataResidencyManager manages residency policies.
type DataResidencyManager struct {
	db *DB
}

// NewDataResidencyManager creates a new residency manager.
func NewDataResidencyManager(db *DB) *DataResidencyManager {
	return &DataResidencyManager{db: db}
}

// AddPolicy adds a residency policy.
func (drm *DataResidencyManager) AddPolicy(ctx context.Context, policy *DataResidencyPolicy) error {
	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("residency:%s", policy.PathPrefix)
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return drm.db.Put([]byte("residency:policy:"+policy.PolicyID), data)
}

// ValidateResidency checks if region is allowed for a path.
func (drm *DataResidencyManager) ValidateResidency(ctx context.Context, path, region string) (bool, *DataResidencyPolicy, error) {
	policies, err := drm.listPolicies()
	if err != nil {
		return false, nil, err
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if strings.HasPrefix(path, policy.PathPrefix) {
			for _, allowed := range policy.Regions {
				if strings.EqualFold(allowed, region) {
					return true, &policy, nil
				}
			}
			return false, &policy, nil
		}
	}
	return true, nil, nil
}

func (drm *DataResidencyManager) listPolicies() ([]DataResidencyPolicy, error) {
	keys, err := drm.db.Keys("residency:policy:*")
	if err != nil {
		return nil, err
	}
	policies := make([]DataResidencyPolicy, 0)
	for _, key := range keys {
		data, err := drm.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var policy DataResidencyPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			continue
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

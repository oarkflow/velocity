package velocity

import (
	"fmt"
)

// SoDPolicy defines segregation-of-duties constraints.
type SoDPolicy struct {
	PolicyID          string   `json:"policy_id"`
	Name              string   `json:"name"`
	IncompatibleRoles []string `json:"incompatible_roles"`
	Enabled           bool     `json:"enabled"`
}

// SoDManager validates role assignments.
type SoDManager struct {
	policies []SoDPolicy
}

// NewSoDManager creates a new SoD manager.
func NewSoDManager() *SoDManager {
	return &SoDManager{policies: make([]SoDPolicy, 0)}
}

// AddPolicy adds a segregation-of-duties policy.
func (sm *SoDManager) AddPolicy(policy SoDPolicy) {
	sm.policies = append(sm.policies, policy)
}

// ValidateAssignment checks whether roles violate any SoD policy.
func (sm *SoDManager) ValidateAssignment(roles []string) error {
	roleSet := make(map[string]struct{})
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}

	for _, policy := range sm.policies {
		if !policy.Enabled {
			continue
		}
		conflicts := 0
		for _, r := range policy.IncompatibleRoles {
			if _, ok := roleSet[r]; ok {
				conflicts++
			}
		}
		if conflicts > 1 {
			return fmt.Errorf("SoD violation: policy %s", policy.Name)
		}
	}
	return nil
}

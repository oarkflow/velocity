package velocity

import (
	"context"
	"encoding/json"
	"fmt"
)

// AddPolicy adds or updates a compliance policy.
func (pe *PolicyEngine) AddPolicy(ctx context.Context, policy *CompliancePolicy) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("policy:%s", policy.Name)
	}
	if policy.EnforcementMode == "" {
		policy.EnforcementMode = "enforce"
	}

	pe.policies[policy.PolicyID] = policy

	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	return pe.db.Put([]byte("policy:"+policy.PolicyID), data)
}

// ListPolicies returns all policies.
func (pe *PolicyEngine) ListPolicies(ctx context.Context) ([]*CompliancePolicy, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policies := make([]*CompliancePolicy, 0, len(pe.policies))
	for _, p := range pe.policies {
		policies = append(policies, p)
	}
	return policies, nil
}

// LoadPolicies loads policies from storage.
func (pe *PolicyEngine) LoadPolicies(ctx context.Context) error {
	keys, err := pe.db.Keys("policy:*")
	if err != nil {
		return err
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	for _, key := range keys {
		data, err := pe.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var policy CompliancePolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			continue
		}
		pe.policies[policy.PolicyID] = &policy
	}

	return nil
}

// EvaluatePolicies evaluates policies for a request.
func (pe *PolicyEngine) EvaluatePolicies(
	ctx context.Context,
	frameworks []ComplianceFramework,
	req *ComplianceOperationRequest,
	tag *ComplianceTag,
	result *ComplianceValidationResult,
) error {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	for _, policy := range pe.policies {
		if !policy.Enabled {
			continue
		}
		if !containsFramework(frameworks, policy.Framework) {
			continue
		}

		for _, rule := range policy.Rules {
			if !ruleMatches(rule, req, tag) {
				continue
			}

			switch rule.Action {
			case "deny":
				if policy.EnforcementMode == "enforce" {
					result.Allowed = false
				}
				result.ViolatedRules = append(result.ViolatedRules, fmt.Sprintf("policy %s rule %s denied", policy.PolicyID, rule.RuleID))
			case "alert":
				result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("policy alert: %s", rule.RuleID))
			case "allow":
				// No-op
			}
		}
	}

	return nil
}

func ruleMatches(rule PolicyRule, req *ComplianceOperationRequest, tag *ComplianceTag) bool {
	// Evaluate based on parameters
	params := rule.Parameters
	if params == nil {
		return true
	}

	if ops, ok := params["operations"].([]interface{}); ok {
		matched := false
		for _, o := range ops {
			if op, ok := o.(string); ok && op == req.Operation {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if minClass, ok := params["min_data_class"].(string); ok {
		if dataClassValue(tag.DataClass) < dataClassValue(DataClassification(minClass)) {
			return false
		}
	}

	if requireEnc, ok := params["require_encryption"].(bool); ok && requireEnc {
		if !req.Encrypted {
			return true
		}
	}

	if requireMFA, ok := params["require_mfa"].(bool); ok && requireMFA {
		if !req.MFAVerified {
			return true
		}
	}

	if requireActor, ok := params["require_actor"].(bool); ok && requireActor {
		if req.Actor == "" {
			return true
		}
	}

	if region, ok := params["require_region"].(string); ok && region != "" {
		if req.Region != region {
			return true
		}
	}

	return false
}

func dataClassValue(class DataClassification) int {
	switch class {
	case DataClassPublic:
		return 1
	case DataClassInternal:
		return 2
	case DataClassConfidential:
		return 3
	case DataClassRestricted:
		return 4
	case DataClassTopSecret:
		return 5
	default:
		return 0
	}
}

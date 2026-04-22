package velocity

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// IAM Policy Effect constants
const (
	IAMEffectAllow = "Allow"
	IAMEffectDeny  = "Deny"
)

// IAM store key prefixes
const (
	iamPolicyPrefix = "iam:policy:"
	iamUserPrefix   = "iam:user:"
	iamGroupPrefix  = "iam:group:"
)

// IAMPolicy represents an AWS IAM-style policy document.
type IAMPolicy struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Statements []IAMStatement `json:"statements"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// IAMStatement represents a single statement within an IAM policy.
type IAMStatement struct {
	Sid       string            `json:"sid,omitempty"`
	Effect    string            `json:"effect"`     // "Allow" or "Deny"
	Principal []string          `json:"principal"`   // user IDs, "*" for all
	Action    []string          `json:"action"`      // e.g. "s3:GetObject", "s3:*"
	Resource  []string          `json:"resource"`    // ARN patterns, e.g. "arn:velocity:s3:::bucket/*"
	Condition *IAMConditionBlock `json:"condition,omitempty"`
}

// IAMConditionBlock holds condition operators and their key-value checks.
type IAMConditionBlock struct {
	StringEquals map[string]string `json:"StringEquals,omitempty"`
	StringLike   map[string]string `json:"StringLike,omitempty"`
	IpAddress    map[string]string `json:"IpAddress,omitempty"`
	DateLessThan map[string]string `json:"DateLessThan,omitempty"`
}

// IAMUserAttachment stores the list of policy names attached to a user.
type IAMUserAttachment struct {
	UserID   string   `json:"user_id"`
	Policies []string `json:"policies"`
}

// IAMGroupAttachment stores the list of policy names attached to a group.
type IAMGroupAttachment struct {
	GroupID  string   `json:"group_id"`
	Policies []string `json:"policies"`
}

// IAMEvalRequest represents a request to evaluate access.
type IAMEvalRequest struct {
	Principal string            `json:"principal"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Context   map[string]string `json:"context,omitempty"` // ip, date, custom keys
}

// IAMEvalResult represents the result of a policy evaluation.
type IAMEvalResult struct {
	Allowed       bool   `json:"allowed"`
	ExplicitDeny  bool   `json:"explicit_deny"`
	MatchedPolicy string `json:"matched_policy,omitempty"`
	Reason        string `json:"reason"`
}

// IAMPolicyEngine manages IAM policies, user/group attachments, and access evaluation.
type IAMPolicyEngine struct {
	db *DB
	mu sync.RWMutex
}

// NewIAMPolicyEngine creates a new IAM policy engine backed by the given DB.
func NewIAMPolicyEngine(db *DB) *IAMPolicyEngine {
	return &IAMPolicyEngine{db: db}
}

// CreatePolicy stores a new IAM policy.
func (e *IAMPolicyEngine) CreatePolicy(policy *IAMPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if policy.Name == "" {
		return fmt.Errorf("iam: policy name is required")
	}
	if policy.Version == "" {
		policy.Version = "2012-10-17"
	}
	for i := range policy.Statements {
		s := &policy.Statements[i]
		if s.Effect != IAMEffectAllow && s.Effect != IAMEffectDeny {
			return fmt.Errorf("iam: statement %q has invalid effect %q", s.Sid, s.Effect)
		}
	}
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("iam: failed to marshal policy: %w", err)
	}
	return e.db.Put([]byte(iamPolicyPrefix+policy.Name), data)
}

// DeletePolicy removes an IAM policy by name.
func (e *IAMPolicyEngine) DeletePolicy(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.db.Delete([]byte(iamPolicyPrefix + name))
}

// GetPolicy retrieves a policy by name.
func (e *IAMPolicyEngine) GetPolicy(name string) (*IAMPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	data, err := e.db.Get([]byte(iamPolicyPrefix + name))
	if err != nil {
		return nil, fmt.Errorf("iam: policy %q not found: %w", name, err)
	}
	var policy IAMPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("iam: failed to unmarshal policy: %w", err)
	}
	return &policy, nil
}

// ListPolicies returns all stored IAM policies.
func (e *IAMPolicyEngine) ListPolicies() ([]*IAMPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	keys, err := e.db.Keys(iamPolicyPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("iam: failed to list policies: %w", err)
	}
	policies := make([]*IAMPolicy, 0, len(keys))
	for _, key := range keys {
		data, err := e.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var p IAMPolicy
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		policies = append(policies, &p)
	}
	return policies, nil
}

// AttachUserPolicy attaches a policy to a user.
func (e *IAMPolicyEngine) AttachUserPolicy(userID, policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Verify policy exists
	if !e.db.Has([]byte(iamPolicyPrefix + policyName)) {
		return fmt.Errorf("iam: policy %q not found", policyName)
	}

	att := e.getUserAttachment(userID)
	for _, p := range att.Policies {
		if p == policyName {
			return nil // already attached
		}
	}
	att.Policies = append(att.Policies, policyName)
	return e.saveUserAttachment(att)
}

// DetachUserPolicy removes a policy from a user.
func (e *IAMPolicyEngine) DetachUserPolicy(userID, policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	att := e.getUserAttachment(userID)
	filtered := make([]string, 0, len(att.Policies))
	found := false
	for _, p := range att.Policies {
		if p == policyName {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}
	if !found {
		return fmt.Errorf("iam: policy %q not attached to user %q", policyName, userID)
	}
	att.Policies = filtered
	return e.saveUserAttachment(att)
}

// AttachGroupPolicy attaches a policy to a group.
func (e *IAMPolicyEngine) AttachGroupPolicy(groupID, policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.db.Has([]byte(iamPolicyPrefix + policyName)) {
		return fmt.Errorf("iam: policy %q not found", policyName)
	}

	att := e.getGroupAttachment(groupID)
	for _, p := range att.Policies {
		if p == policyName {
			return nil
		}
	}
	att.Policies = append(att.Policies, policyName)
	return e.saveGroupAttachment(att)
}

// DetachGroupPolicy removes a policy from a group.
func (e *IAMPolicyEngine) DetachGroupPolicy(groupID, policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	att := e.getGroupAttachment(groupID)
	filtered := make([]string, 0, len(att.Policies))
	found := false
	for _, p := range att.Policies {
		if p == policyName {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}
	if !found {
		return fmt.Errorf("iam: policy %q not attached to group %q", policyName, groupID)
	}
	att.Policies = filtered
	return e.saveGroupAttachment(att)
}

// GetUserPolicies returns the policy names attached to a user.
func (e *IAMPolicyEngine) GetUserPolicies(userID string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getUserAttachment(userID).Policies
}

// EvaluateAccess checks whether a principal is allowed to perform an action on a resource.
// It implements deny-overrides: an explicit Deny in any matching statement wins.
func (e *IAMPolicyEngine) EvaluateAccess(req *IAMEvalRequest) *IAMEvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := &IAMEvalResult{
		Allowed: false,
		Reason:  "no matching policy",
	}

	// Gather all policy names for the principal
	policyNames := e.collectPoliciesForPrincipal(req.Principal)
	if len(policyNames) == 0 {
		return result
	}

	hasAllow := false
	var allowPolicyName string

	for _, pName := range policyNames {
		data, err := e.db.Get([]byte(iamPolicyPrefix + pName))
		if err != nil {
			continue
		}
		var policy IAMPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			continue
		}

		for _, stmt := range policy.Statements {
			if !e.matchesPrincipal(stmt.Principal, req.Principal) {
				continue
			}
			if !e.matchesAction(stmt.Action, req.Action) {
				continue
			}
			if !e.matchesResource(stmt.Resource, req.Resource) {
				continue
			}
			if stmt.Condition != nil && !e.evaluateConditions(stmt.Condition, req.Context) {
				continue
			}

			if stmt.Effect == IAMEffectDeny {
				return &IAMEvalResult{
					Allowed:       false,
					ExplicitDeny:  true,
					MatchedPolicy: pName,
					Reason:        fmt.Sprintf("explicit deny in policy %q, statement %q", pName, stmt.Sid),
				}
			}
			if stmt.Effect == IAMEffectAllow && !hasAllow {
				hasAllow = true
				allowPolicyName = pName
			}
		}
	}

	if hasAllow {
		result.Allowed = true
		result.MatchedPolicy = allowPolicyName
		result.Reason = "allowed by policy"
	}
	return result
}

// collectPoliciesForPrincipal gathers all policy names from user and group attachments.
func (e *IAMPolicyEngine) collectPoliciesForPrincipal(principal string) []string {
	seen := make(map[string]struct{})
	var result []string

	// User policies
	att := e.getUserAttachment(principal)
	for _, p := range att.Policies {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}

	// Group policies - look for groups that contain this user.
	keys, err := e.db.Keys(iamGroupPrefix + "*")
	if err == nil {
		for _, key := range keys {
			data, _ := e.db.Get([]byte(key))
			if data == nil {
				continue
			}
			var gatt IAMGroupAttachment
			if json.Unmarshal(data, &gatt) != nil {
				continue
			}
			// Group policies apply to all members; we attach them to the group,
			// and treat the principal as potentially in all groups.
			// In a full implementation, group membership would be tracked separately.
			// Here, policies with Principal "*" will still match.
			for _, p := range gatt.Policies {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					result = append(result, p)
				}
			}
		}
	}

	return result
}

// matchesPrincipal checks if a statement's principal list matches the given principal.
func (e *IAMPolicyEngine) matchesPrincipal(principals []string, principal string) bool {
	if len(principals) == 0 {
		return true // empty means all
	}
	for _, p := range principals {
		if p == "*" || p == principal {
			return true
		}
	}
	return false
}

// matchesAction checks if the request action matches any of the statement's action patterns.
func (e *IAMPolicyEngine) matchesAction(patterns []string, action string) bool {
	for _, pat := range patterns {
		if iamWildcardMatch(pat, action) {
			return true
		}
	}
	return false
}

// matchesResource checks if the request resource matches any of the statement's resource ARN patterns.
func (e *IAMPolicyEngine) matchesResource(patterns []string, resource string) bool {
	for _, pat := range patterns {
		if iamWildcardMatch(pat, resource) {
			return true
		}
	}
	return false
}

// iamWildcardMatch matches a pattern containing '*' and '?' wildcards against a string.
func iamWildcardMatch(pattern, str string) bool {
	if pattern == "*" {
		return true
	}
	return iamWildcardMatchRecursive(pattern, str, 0, 0)
}

func iamWildcardMatchRecursive(pattern, str string, pi, si int) bool {
	for pi < len(pattern) && si < len(str) {
		switch pattern[pi] {
		case '*':
			// Skip consecutive *
			for pi < len(pattern) && pattern[pi] == '*' {
				pi++
			}
			if pi == len(pattern) {
				return true
			}
			for si <= len(str) {
				if iamWildcardMatchRecursive(pattern, str, pi, si) {
					return true
				}
				si++
			}
			return false
		case '?':
			pi++
			si++
		default:
			if pattern[pi] != str[si] {
				return false
			}
			pi++
			si++
		}
	}
	// Consume trailing *
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern) && si == len(str)
}

// evaluateConditions checks all condition operators in the block.
func (e *IAMPolicyEngine) evaluateConditions(cond *IAMConditionBlock, ctx map[string]string) bool {
	if ctx == nil {
		ctx = make(map[string]string)
	}

	// StringEquals
	for key, expected := range cond.StringEquals {
		actual, ok := ctx[key]
		if !ok || actual != expected {
			return false
		}
	}

	// StringLike (wildcard matching)
	for key, pattern := range cond.StringLike {
		actual, ok := ctx[key]
		if !ok || !iamWildcardMatch(pattern, actual) {
			return false
		}
	}

	// IpAddress - check if the context IP is within the CIDR
	for key, cidr := range cond.IpAddress {
		actual, ok := ctx[key]
		if !ok {
			return false
		}
		if !iamIPInCIDR(actual, cidr) {
			return false
		}
	}

	// DateLessThan - check if context date is before the given date
	for key, dateStr := range cond.DateLessThan {
		actual, ok := ctx[key]
		if !ok {
			return false
		}
		threshold, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			return false
		}
		actualTime, err := time.Parse(time.RFC3339, actual)
		if err != nil {
			return false
		}
		if !actualTime.Before(threshold) {
			return false
		}
	}

	return true
}

// iamIPInCIDR checks whether an IP address falls within a CIDR block.
func iamIPInCIDR(ipStr, cidr string) bool {
	// If cidr has no /, treat as single IP comparison
	if !strings.Contains(cidr, "/") {
		return ipStr == cidr
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return network.Contains(ip)
}

// getUserAttachment loads user policy attachment from DB.
func (e *IAMPolicyEngine) getUserAttachment(userID string) *IAMUserAttachment {
	data, err := e.db.Get([]byte(iamUserPrefix + userID))
	if err != nil || data == nil {
		return &IAMUserAttachment{UserID: userID}
	}
	var att IAMUserAttachment
	if json.Unmarshal(data, &att) != nil {
		return &IAMUserAttachment{UserID: userID}
	}
	return &att
}

func (e *IAMPolicyEngine) saveUserAttachment(att *IAMUserAttachment) error {
	data, err := json.Marshal(att)
	if err != nil {
		return err
	}
	return e.db.Put([]byte(iamUserPrefix+att.UserID), data)
}

// getGroupAttachment loads group policy attachment from DB.
func (e *IAMPolicyEngine) getGroupAttachment(groupID string) *IAMGroupAttachment {
	data, err := e.db.Get([]byte(iamGroupPrefix + groupID))
	if err != nil || data == nil {
		return &IAMGroupAttachment{GroupID: groupID}
	}
	var att IAMGroupAttachment
	if json.Unmarshal(data, &att) != nil {
		return &IAMGroupAttachment{GroupID: groupID}
	}
	return &att
}

func (e *IAMPolicyEngine) saveGroupAttachment(att *IAMGroupAttachment) error {
	data, err := json.Marshal(att)
	if err != nil {
		return err
	}
	return e.db.Put([]byte(iamGroupPrefix+att.GroupID), data)
}

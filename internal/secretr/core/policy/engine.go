// Package policy provides policy definition and enforcement.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrPolicyNotFound  = errors.New("policy: not found")
	ErrPolicyViolation = errors.New("policy: violation detected")
	ErrPolicyFrozen    = errors.New("policy: system is in lockdown mode")
	ErrInvalidPolicy   = errors.New("policy: invalid policy definition")
)

// Engine provides policy management and enforcement
type Engine struct {
	store        *storage.Store
	crypto       *crypto.Engine
	policyStore  *storage.TypedStore[types.Policy]
	bindingStore *storage.TypedStore[PolicyBinding]
	frozen       bool
	dryRun       bool
}

// PolicyBinding binds a policy to a resource
type PolicyBinding struct {
	ID           types.ID        `json:"id"`
	PolicyID     types.ID        `json:"policy_id"`
	ResourceID   types.ID        `json:"resource_id"`
	ResourceType string          `json:"resource_type"`
	CreatedAt    types.Timestamp `json:"created_at"`
	CreatedBy    types.ID        `json:"created_by"`
}

// EngineConfig configures the policy engine
type EngineConfig struct {
	Store *storage.Store
}

// NewEngine creates a new policy engine
func NewEngine(cfg EngineConfig) *Engine {
	return &Engine{
		store:        cfg.Store,
		crypto:       crypto.NewEngine(""),
		policyStore:  storage.NewTypedStore[types.Policy](cfg.Store, storage.CollectionPolicies),
		bindingStore: storage.NewTypedStore[PolicyBinding](cfg.Store, storage.CollectionPolicyBindings),
		frozen:       false,
		dryRun:       false,
	}
}

// Create creates a new policy
func (e *Engine) Create(ctx context.Context, opts CreatePolicyOptions) (*types.Policy, error) {
	if e.frozen {
		return nil, ErrPolicyFrozen
	}

	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Validate rules
	for _, rule := range opts.Rules {
		if err := validateRule(rule); err != nil {
			return nil, err
		}
	}

	now := types.Now()
	policy := &types.Policy{
		ID:          id,
		Name:        opts.Name,
		Description: opts.Description,
		Version:     1,
		Type:        opts.Type,
		Rules:       opts.Rules,
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      types.StatusActive,
	}

	// Sign policy if signer key provided
	if len(opts.SignerKey) > 0 {
		policyData, _ := json.Marshal(policy)
		sig, err := e.crypto.Sign(opts.SignerKey, policyData)
		if err != nil {
			return nil, err
		}
		policy.Signature = sig
		policy.SignedBy = opts.SignerID
	}

	if err := e.policyStore.Set(ctx, string(id), policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// CreatePolicyOptions holds policy creation options
type CreatePolicyOptions struct {
	Name        string
	Description string
	Type        types.PolicyType
	Rules       []types.PolicyRule
	SignerID    types.ID
	SignerKey   []byte
}

func validateRule(rule types.PolicyRule) error {
	if rule.Effect != "allow" && rule.Effect != "deny" {
		return fmt.Errorf("policy: invalid effect %s", rule.Effect)
	}
	if len(rule.Actions) == 0 {
		return errors.New("policy: rule must have at least one action")
	}
	return nil
}

// Get retrieves a policy
func (e *Engine) Get(ctx context.Context, id types.ID) (*types.Policy, error) {
	policy, err := e.policyStore.Get(ctx, string(id))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}
	return policy, nil
}

// List lists all policies
func (e *Engine) List(ctx context.Context) ([]*types.Policy, error) {
	return e.policyStore.List(ctx, "")
}

// Update updates a policy
func (e *Engine) Update(ctx context.Context, id types.ID, opts UpdatePolicyOptions) (*types.Policy, error) {
	if e.frozen {
		return nil, ErrPolicyFrozen
	}

	policy, err := e.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	policy.Description = opts.Description
	policy.Rules = opts.Rules
	policy.Version++
	policy.UpdatedAt = types.Now()
	policy.Signature = nil // Invalidate signature on update

	// Re-sign if key provided
	if len(opts.SignerKey) > 0 {
		policyData, _ := json.Marshal(policy)
		sig, err := e.crypto.Sign(opts.SignerKey, policyData)
		if err != nil {
			return nil, err
		}
		policy.Signature = sig
		policy.SignedBy = opts.SignerID
	}

	if err := e.policyStore.Set(ctx, string(id), policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// UpdatePolicyOptions holds policy update options
type UpdatePolicyOptions struct {
	Description string
	Rules       []types.PolicyRule
	SignerID    types.ID
	SignerKey   []byte
}

// Bind binds a policy to a resource
func (e *Engine) Bind(ctx context.Context, policyID types.ID, resourceID types.ID, resourceType string, creatorID types.ID) error {
	if e.frozen {
		return ErrPolicyFrozen
	}

	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	binding := &PolicyBinding{
		ID:           id,
		PolicyID:     policyID,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		CreatedAt:    types.Now(),
		CreatedBy:    creatorID,
	}

	return e.bindingStore.Set(ctx, string(id), binding)
}

// Evaluate evaluates policies for a resource and action
func (e *Engine) Evaluate(ctx context.Context, request EvaluationRequest) (*EvaluationResult, error) {
	// Get all bindings for the resource
	bindings, err := e.bindingStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := &EvaluationResult{
		Allowed:    true,
		Violations: make([]Violation, 0),
	}

	for _, binding := range bindings {
		if binding.ResourceID != request.ResourceID {
			continue
		}

		policy, err := e.Get(ctx, binding.PolicyID)
		if err != nil {
			continue
		}

		// Evaluate each rule
		for _, rule := range policy.Rules {
			matches := matchesRule(rule, request)
			if !matches {
				continue
			}

			if rule.Effect == "deny" {
				if !e.dryRun {
					result.Allowed = false
				}
				reason := "Denied by policy rule"
				if e.dryRun {
					reason = "Would be denied by policy rule (dry-run)"
				}
				result.Violations = append(result.Violations, Violation{
					PolicyID:   policy.ID,
					PolicyName: policy.Name,
					RuleID:     rule.ID,
					Action:     request.Action,
					Reason:     reason,
				})
			}
		}
	}

	return result, nil
}

// EnableDryRun enables dry-run mode where deny rules are reported but not enforced.
func (e *Engine) EnableDryRun() {
	e.dryRun = true
}

// DisableDryRun disables dry-run mode.
func (e *Engine) DisableDryRun() {
	e.dryRun = false
}

// DryRunEnabled returns dry-run mode state.
func (e *Engine) DryRunEnabled() bool {
	return e.dryRun
}

// EvaluationRequest represents a policy evaluation request
type EvaluationRequest struct {
	ActorID      types.ID
	ResourceID   types.ID
	ResourceType string
	Action       string
	Context      map[string]any
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Allowed    bool
	Violations []Violation
}

// Violation represents a policy violation
type Violation struct {
	PolicyID   types.ID
	PolicyName string
	RuleID     types.ID
	Action     string
	Reason     string
}

func matchesRule(rule types.PolicyRule, request EvaluationRequest) bool {
	// Check if action matches
	actionMatches := false
	for _, action := range rule.Actions {
		if matchPattern(action, request.Action) {
			actionMatches = true
			break
		}
	}
	if !actionMatches {
		return false
	}

	// Check if resource matches
	resourceMatches := len(rule.Resources) == 0 // Empty means all resources
	for _, resource := range rule.Resources {
		if matchPattern(resource, string(request.ResourceID)) {
			resourceMatches = true
			break
		}
	}

	return resourceMatches
}

func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// Simple glob pattern matching
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = regexp.MustCompile(`\\\*`).ReplaceAllString(regexPattern, ".*")
	regexPattern += "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return pattern == value
	}
	return re.MatchString(value)
}

// Simulate simulates policy evaluation without enforcement
func (e *Engine) Simulate(ctx context.Context, request EvaluationRequest) (*SimulationResult, error) {
	result, err := e.Evaluate(ctx, request)
	if err != nil {
		return nil, err
	}

	return &SimulationResult{
		Request:          request,
		EvaluationResult: *result,
		SimulatedAt:      time.Now(),
	}, nil
}

// SimulationResult contains simulation results
type SimulationResult struct {
	Request          EvaluationRequest
	EvaluationResult EvaluationResult
	SimulatedAt      time.Time
}

// Freeze enables policy lockdown mode
func (e *Engine) Freeze() {
	e.frozen = true
}

// Unfreeze disables policy lockdown mode
func (e *Engine) Unfreeze() {
	e.frozen = false
}

// IsFrozen returns whether policies are frozen
func (e *Engine) IsFrozen() bool {
	return e.frozen
}

// VerifySignature verifies a policy's signature
func (e *Engine) VerifySignature(policy *types.Policy, signerPubKey []byte) error {
	if len(policy.Signature) == 0 {
		return errors.New("policy: policy is not signed")
	}

	// Create copy without signature for verification
	policyCopy := *policy
	policyCopy.Signature = nil

	policyData, err := json.Marshal(policyCopy)
	if err != nil {
		return err
	}

	return e.crypto.Verify(signerPubKey, policyData, policy.Signature)
}

// Close cleans up resources
func (e *Engine) Close() error {
	return e.crypto.Close()
}

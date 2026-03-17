// Package secrets provides workflow-aware secrets management.
package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrWorkflowBindingNotFound  = errors.New("workflow: binding not found")
	ErrWorkflowValidationFailed = errors.New("workflow: validation failed")
	ErrPipelineNotAuthorized    = errors.New("workflow: pipeline not authorized")
	ErrEnvironmentNotAllowed    = errors.New("workflow: environment not allowed")
	ErrBranchNotAllowed         = errors.New("workflow: branch not allowed")
	ErrTTLExpired               = errors.New("workflow: TTL expired")
	ErrMaxUsageExceeded         = errors.New("workflow: max usage exceeded")
)

// WorkflowType represents the type of CI/CD workflow
type WorkflowType string

const (
	WorkflowTypeGitHubActions    WorkflowType = "github_actions"
	WorkflowTypeGitLabCI         WorkflowType = "gitlab_ci"
	WorkflowTypeJenkins          WorkflowType = "jenkins"
	WorkflowTypeCircleCI         WorkflowType = "circleci"
	WorkflowTypeBitbucket        WorkflowType = "bitbucket"
	WorkflowTypeAzureDevOps      WorkflowType = "azure_devops"
	WorkflowTypeGoogleCloudBuild WorkflowType = "cloud_build"
	WorkflowTypeCustom           WorkflowType = "custom"
)

// WorkflowBinding represents a binding between a secret and a workflow
type WorkflowBinding struct {
	ID           types.ID     `json:"id"`
	SecretID     types.ID     `json:"secret_id"`
	WorkflowType WorkflowType `json:"workflow_type"`
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"`

	// Repository restrictions
	RepositoryID      string   `json:"repository_id,omitempty"`
	RepositoryPattern string   `json:"repository_pattern,omitempty"`
	BranchPatterns    []string `json:"branch_patterns,omitempty"`
	TagPatterns       []string `json:"tag_patterns,omitempty"`

	// Environment restrictions
	AllowedEnvironments []string `json:"allowed_environments,omitempty"`
	AllowedRunners      []string `json:"allowed_runners,omitempty"`

	// Workflow restrictions
	AllowedWorkflows []string `json:"allowed_workflows,omitempty"`
	AllowedActors    []string `json:"allowed_actors,omitempty"`

	// Time-based restrictions
	ValidFrom     *time.Time    `json:"valid_from,omitempty"`
	ValidUntil    *time.Time    `json:"valid_until,omitempty"`
	TTL           time.Duration `json:"ttl,omitempty"` // Per-access TTL
	MaxUsages     int           `json:"max_usages,omitempty"`
	CurrentUsages int           `json:"current_usages"`

	// Auto-rotation
	AutoRotate       bool          `json:"auto_rotate"`
	RotateOnDeploy   bool          `json:"rotate_on_deploy"`
	RotationInterval time.Duration `json:"rotation_interval,omitempty"`
	LastRotated      *time.Time    `json:"last_rotated,omitempty"`

	// Audit
	CreatedAt types.Timestamp    `json:"created_at"`
	UpdatedAt types.Timestamp    `json:"updated_at"`
	CreatedBy types.ID           `json:"created_by"`
	Status    types.EntityStatus `json:"status"`
}

// WorkflowContext represents the context of a workflow requesting a secret
type WorkflowContext struct {
	WorkflowType   WorkflowType `json:"workflow_type"`
	RepositoryID   string       `json:"repository_id"`
	RepositoryName string       `json:"repository_name,omitempty"`
	Branch         string       `json:"branch,omitempty"`
	Tag            string       `json:"tag,omitempty"`
	CommitSHA      string       `json:"commit_sha,omitempty"`
	Environment    string       `json:"environment,omitempty"`
	WorkflowName   string       `json:"workflow_name,omitempty"`
	WorkflowID     string       `json:"workflow_id,omitempty"`
	JobName        string       `json:"job_name,omitempty"`
	RunnerName     string       `json:"runner_name,omitempty"`
	Actor          string       `json:"actor,omitempty"`
	TriggerEvent   string       `json:"trigger_event,omitempty"`
	RunID          string       `json:"run_id,omitempty"`
	OIDC           *OIDCClaims  `json:"oidc,omitempty"`
}

// OIDCClaims represents OIDC claims from CI/CD providers
type OIDCClaims struct {
	Subject      string `json:"sub"`
	Audience     string `json:"aud"`
	Issuer       string `json:"iss"`
	Repository   string `json:"repository,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	Environment  string `json:"environment,omitempty"`
	Ref          string `json:"ref,omitempty"`
	RefType      string `json:"ref_type,omitempty"`
	Workflow     string `json:"workflow,omitempty"`
	Actor        string `json:"actor,omitempty"`
}

// WorkflowAccessLog represents a log of workflow access to secrets
type WorkflowAccessLog struct {
	ID           types.ID         `json:"id"`
	BindingID    types.ID         `json:"binding_id"`
	SecretID     types.ID         `json:"secret_id"`
	Context      *WorkflowContext `json:"context"`
	Allowed      bool             `json:"allowed"`
	DenialReason string           `json:"denial_reason,omitempty"`
	Timestamp    time.Time        `json:"timestamp"`
	IPAddress    string           `json:"ip_address,omitempty"`
}

// JustInTimeSecret represents a short-lived secret for a specific run
type JustInTimeSecret struct {
	ID          types.ID         `json:"id"`
	BindingID   types.ID         `json:"binding_id"`
	SecretValue []byte           `json:"secret_value"` // Encrypted
	Context     *WorkflowContext `json:"context"`
	ExpiresAt   time.Time        `json:"expires_at"`
	MaxUses     int              `json:"max_uses"`
	CurrentUses int              `json:"current_uses"`
	CreatedAt   time.Time        `json:"created_at"`
	Hash        string           `json:"hash"` // For tracking
}

// WorkflowManager manages workflow-aware secrets
type WorkflowManager struct {
	mu           sync.RWMutex
	store        *storage.Store
	crypto       *crypto.Engine
	bindingStore *storage.TypedStore[WorkflowBinding]
	logStore     *storage.TypedStore[WorkflowAccessLog]
	jitStore     *storage.TypedStore[JustInTimeSecret]
	bindings     map[types.ID]*WorkflowBinding
	secretGetter func(ctx context.Context, id types.ID) ([]byte, error)
}

// WorkflowManagerConfig configures the workflow manager
type WorkflowManagerConfig struct {
	Store        *storage.Store
	SecretGetter func(ctx context.Context, id types.ID) ([]byte, error)
}

// NewWorkflowManager creates a new workflow manager
func NewWorkflowManager(cfg WorkflowManagerConfig) *WorkflowManager {
	m := &WorkflowManager{
		store:        cfg.Store,
		crypto:       crypto.NewEngine(""),
		bindingStore: storage.NewTypedStore[WorkflowBinding](cfg.Store, "workflow_bindings"),
		logStore:     storage.NewTypedStore[WorkflowAccessLog](cfg.Store, "workflow_logs"),
		jitStore:     storage.NewTypedStore[JustInTimeSecret](cfg.Store, "jit_secrets"),
		bindings:     make(map[types.ID]*WorkflowBinding),
		secretGetter: cfg.SecretGetter,
	}

	// Load existing bindings
	ctx := context.Background()
	bindings, _ := m.bindingStore.List(ctx, "")
	for _, b := range bindings {
		m.bindings[b.ID] = b
	}

	return m
}

// CreateBinding creates a new workflow binding
func (m *WorkflowManager) CreateBinding(ctx context.Context, binding *WorkflowBinding) error {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	binding.ID = id
	binding.CreatedAt = types.Now()
	binding.UpdatedAt = types.Now()
	binding.Status = types.StatusActive

	if err := m.bindingStore.Set(ctx, string(binding.ID), binding); err != nil {
		return err
	}

	m.mu.Lock()
	m.bindings[binding.ID] = binding
	m.mu.Unlock()

	return nil
}

// GetBinding retrieves a binding by ID
func (m *WorkflowManager) GetBinding(ctx context.Context, id types.ID) (*WorkflowBinding, error) {
	m.mu.RLock()
	if b, ok := m.bindings[id]; ok {
		m.mu.RUnlock()
		return b, nil
	}
	m.mu.RUnlock()
	return m.bindingStore.Get(ctx, string(id))
}

// GetBindingsForSecret retrieves all bindings for a secret
func (m *WorkflowManager) GetBindingsForSecret(ctx context.Context, secretID types.ID) ([]*WorkflowBinding, error) {
	all, err := m.bindingStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var bindings []*WorkflowBinding
	for _, b := range all {
		if b.SecretID == secretID && b.Status == types.StatusActive {
			bindings = append(bindings, b)
		}
	}

	return bindings, nil
}

// UpdateBinding updates a binding
func (m *WorkflowManager) UpdateBinding(ctx context.Context, id types.ID, binding *WorkflowBinding) error {
	binding.ID = id
	binding.UpdatedAt = types.Now()

	if err := m.bindingStore.Set(ctx, string(id), binding); err != nil {
		return err
	}

	m.mu.Lock()
	m.bindings[id] = binding
	m.mu.Unlock()

	return nil
}

// DeleteBinding deletes a binding
func (m *WorkflowManager) DeleteBinding(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	delete(m.bindings, id)
	m.mu.Unlock()
	return m.bindingStore.Delete(ctx, string(id))
}

// ValidateAccess validates access to a secret from a workflow context
func (m *WorkflowManager) ValidateAccess(ctx context.Context, secretID types.ID, workflowCtx *WorkflowContext) (*ValidationResult, error) {
	bindings, err := m.GetBindingsForSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	result := &ValidationResult{
		Allowed: false,
		Reason:  "No matching workflow binding found",
	}

	for _, binding := range bindings {
		if binding.Status != types.StatusActive {
			continue
		}

		// Check workflow type
		if binding.WorkflowType != workflowCtx.WorkflowType {
			continue
		}

		validationErr := m.validateBinding(binding, workflowCtx)
		if validationErr == nil {
			// Access allowed
			result.Allowed = true
			result.Reason = ""
			result.BindingID = binding.ID

			// Increment usage counter
			binding.CurrentUsages++
			binding.UpdatedAt = types.Now()
			_ = m.bindingStore.Set(ctx, string(binding.ID), binding)

			// Log access
			_ = m.logAccess(ctx, binding.ID, secretID, workflowCtx, true, "")

			return result, nil
		}
	}

	// Log denied access
	_ = m.logAccess(ctx, "", secretID, workflowCtx, false, result.Reason)

	return result, nil
}

// validateBinding validates a specific binding against context
func (m *WorkflowManager) validateBinding(binding *WorkflowBinding, ctx *WorkflowContext) error {
	// Check time validity
	now := time.Now()
	if binding.ValidFrom != nil && now.Before(*binding.ValidFrom) {
		return ErrWorkflowValidationFailed
	}
	if binding.ValidUntil != nil && now.After(*binding.ValidUntil) {
		return ErrTTLExpired
	}

	// Check max usages
	if binding.MaxUsages > 0 && binding.CurrentUsages >= binding.MaxUsages {
		return ErrMaxUsageExceeded
	}

	// Check repository
	if binding.RepositoryID != "" && binding.RepositoryID != ctx.RepositoryID {
		return ErrPipelineNotAuthorized
	}

	if binding.RepositoryPattern != "" {
		matched, _ := regexp.MatchString(binding.RepositoryPattern, ctx.RepositoryName)
		if !matched {
			return ErrPipelineNotAuthorized
		}
	}

	// Check branch
	if len(binding.BranchPatterns) > 0 && ctx.Branch != "" {
		matched := false
		for _, pattern := range binding.BranchPatterns {
			if patternMatches(pattern, ctx.Branch) {
				matched = true
				break
			}
		}
		if !matched {
			return ErrBranchNotAllowed
		}
	}

	// Check environment
	if len(binding.AllowedEnvironments) > 0 && ctx.Environment != "" {
		found := false
		for _, env := range binding.AllowedEnvironments {
			if env == ctx.Environment {
				found = true
				break
			}
		}
		if !found {
			return ErrEnvironmentNotAllowed
		}
	}

	// Check workflow
	if len(binding.AllowedWorkflows) > 0 && ctx.WorkflowName != "" {
		found := false
		for _, wf := range binding.AllowedWorkflows {
			if wf == ctx.WorkflowName {
				found = true
				break
			}
		}
		if !found {
			return ErrPipelineNotAuthorized
		}
	}

	// Check actors
	if len(binding.AllowedActors) > 0 && ctx.Actor != "" {
		found := false
		for _, actor := range binding.AllowedActors {
			if actor == ctx.Actor {
				found = true
				break
			}
		}
		if !found {
			return ErrPipelineNotAuthorized
		}
	}

	return nil
}

// patternMatches checks if a string matches a glob-like pattern
func patternMatches(pattern, str string) bool {
	// Simple glob matching (* for wildcard)
	regex := "^" + regexp.QuoteMeta(pattern) + "$"
	regex = regexp.MustCompile(`\\\*`).ReplaceAllString(regex, ".*")
	matched, _ := regexp.MatchString(regex, str)
	return matched
}

// ValidationResult represents the result of access validation
type ValidationResult struct {
	Allowed   bool     `json:"allowed"`
	Reason    string   `json:"reason,omitempty"`
	BindingID types.ID `json:"binding_id,omitempty"`
}

// logAccess logs an access attempt
func (m *WorkflowManager) logAccess(ctx context.Context, bindingID, secretID types.ID, workflowCtx *WorkflowContext, allowed bool, reason string) error {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	log := &WorkflowAccessLog{
		ID:           id,
		BindingID:    bindingID,
		SecretID:     secretID,
		Context:      workflowCtx,
		Allowed:      allowed,
		DenialReason: reason,
		Timestamp:    time.Now(),
	}

	return m.logStore.Set(ctx, string(log.ID), log)
}

// GenerateJITSecret generates a just-in-time secret for a workflow run
func (m *WorkflowManager) GenerateJITSecret(ctx context.Context, bindingID types.ID, workflowCtx *WorkflowContext) (*JustInTimeSecret, error) {
	binding, err := m.GetBinding(ctx, bindingID)
	if err != nil {
		return nil, err
	}

	// Validate access first
	if err := m.validateBinding(binding, workflowCtx); err != nil {
		return nil, err
	}

	// Get the actual secret value
	if m.secretGetter == nil {
		return nil, errors.New("secret getter not configured")
	}

	secretValue, err := m.secretGetter(ctx, binding.SecretID)
	if err != nil {
		return nil, err
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Calculate TTL
	ttl := binding.TTL
	if ttl == 0 {
		ttl = 15 * time.Minute // Default 15 minutes
	}

	// Hash for tracking
	hashData := append([]byte(id), secretValue...)
	hash := sha256.Sum256(hashData)

	jit := &JustInTimeSecret{
		ID:          id,
		BindingID:   bindingID,
		SecretValue: secretValue, // Should be encrypted
		Context:     workflowCtx,
		ExpiresAt:   time.Now().Add(ttl),
		MaxUses:     1, // Single use by default
		CurrentUses: 0,
		CreatedAt:   time.Now(),
		Hash:        hex.EncodeToString(hash[:]),
	}

	if err := m.jitStore.Set(ctx, string(jit.ID), jit); err != nil {
		return nil, err
	}

	return jit, nil
}

// RedeemJITSecret redeems a just-in-time secret
func (m *WorkflowManager) RedeemJITSecret(ctx context.Context, id types.ID) ([]byte, error) {
	jit, err := m.jitStore.Get(ctx, string(id))
	if err != nil {
		return nil, err
	}

	// Check expiry
	if time.Now().After(jit.ExpiresAt) {
		_ = m.jitStore.Delete(ctx, string(id))
		return nil, ErrTTLExpired
	}

	// Check usage
	if jit.MaxUses > 0 && jit.CurrentUses >= jit.MaxUses {
		_ = m.jitStore.Delete(ctx, string(id))
		return nil, ErrMaxUsageExceeded
	}

	// Increment usage
	jit.CurrentUses++
	if jit.CurrentUses >= jit.MaxUses {
		// Delete after final use
		_ = m.jitStore.Delete(ctx, string(id))
	} else {
		_ = m.jitStore.Set(ctx, string(id), jit)
	}

	return jit.SecretValue, nil
}

// GetAccessLogs retrieves access logs for a secret
func (m *WorkflowManager) GetAccessLogs(ctx context.Context, secretID types.ID) ([]*WorkflowAccessLog, error) {
	all, err := m.logStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var logs []*WorkflowAccessLog
	for _, log := range all {
		if log.SecretID == secretID {
			logs = append(logs, log)
		}
	}

	return logs, nil
}

// CheckRotationNeeded checks if a binding needs rotation
func (m *WorkflowManager) CheckRotationNeeded(ctx context.Context, bindingID types.ID) (bool, error) {
	binding, err := m.GetBinding(ctx, bindingID)
	if err != nil {
		return false, err
	}

	if !binding.AutoRotate || binding.RotationInterval == 0 {
		return false, nil
	}

	if binding.LastRotated == nil {
		return true, nil
	}

	return time.Since(*binding.LastRotated) > binding.RotationInterval, nil
}

// MarkRotated marks a binding as rotated
func (m *WorkflowManager) MarkRotated(ctx context.Context, bindingID types.ID) error {
	binding, err := m.GetBinding(ctx, bindingID)
	if err != nil {
		return err
	}

	now := time.Now()
	binding.LastRotated = &now
	binding.UpdatedAt = types.Now()

	return m.bindingStore.Set(ctx, string(bindingID), binding)
}

// ExportBindingsReport exports a report of all bindings
func (m *WorkflowManager) ExportBindingsReport(ctx context.Context) ([]byte, error) {
	bindings, err := m.bindingStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(bindings, "", "  ")
}

// Close cleans up resources
func (m *WorkflowManager) Close() error {
	return m.crypto.Close()
}

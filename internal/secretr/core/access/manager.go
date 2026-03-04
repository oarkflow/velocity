// Package access provides access control and delegation functionality.
package access

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrGrantNotFound    = errors.New("access: grant not found")
	ErrGrantExpired     = errors.New("access: grant expired")
	ErrGrantRevoked     = errors.New("access: grant revoked")
	ErrAccessDenied     = errors.New("access: access denied")
	ErrDelegationDenied = errors.New("access: delegation not allowed")
	ErrConflict         = errors.New("access: access conflict detected")
)

// Manager handles access control and delegation
type Manager struct {
	store        *storage.Store
	crypto       *crypto.Engine
	grantStore   *storage.TypedStore[types.AccessGrant]
	roleStore    *storage.TypedStore[types.Role]
	requestStore *storage.TypedStore[types.AccessRequest]
}

// ManagerConfig configures the access manager
type ManagerConfig struct {
	Store *storage.Store
}

// NewManager creates a new access manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:        cfg.Store,
		crypto:       crypto.NewEngine(""),
		grantStore:   storage.NewTypedStore[types.AccessGrant](cfg.Store, storage.CollectionGrants),
		roleStore:    storage.NewTypedStore[types.Role](cfg.Store, storage.CollectionRoles),
		requestStore: storage.NewTypedStore[types.AccessRequest](cfg.Store, storage.CollectionAccessRequests),
	}
}

// Access Request Management

// CreateAccessRequest creates a JIT access request
func (m *Manager) CreateAccessRequest(ctx context.Context, opts CreateAccessRequestOptions) (*types.AccessRequest, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()

	// Default expiry 24 hours if not approved
	expiresAt := types.Timestamp(time.Now().Add(24 * time.Hour).UnixNano())

	req := &types.AccessRequest{
		ID:            id,
		RequestorID:   opts.RequestorID,
		ResourceID:    opts.ResourceID,
		ResourceType:  opts.ResourceType,
		Permissions:   opts.Permissions,
		Role:          opts.Role,
		Justification: opts.Justification,
		Duration:      opts.Duration,
		Status:        types.AccessRequestStatusPending,
		ApproverIDs:   opts.ApproverIDs,
		MinApprovals:  opts.MinApprovals,
		ApprovalCount: 0,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     expiresAt,
	}

	if err := m.requestStore.Set(ctx, string(id), req); err != nil {
		return nil, err
	}

	return req, nil
}

// CreateAccessRequestOptions holds options for creating an access request
type CreateAccessRequestOptions struct {
	RequestorID   types.ID
	ResourceID    types.ID
	ResourceType  string
	Role          string
	Permissions   []string
	Justification string
	Duration      string
	ApproverIDs   []types.ID
	MinApprovals  int
}

// ApproveAccessRequest approves an access request
func (m *Manager) ApproveAccessRequest(ctx context.Context, requestID types.ID, approverID types.ID, notes string) (*types.AccessRequest, error) {
	req, err := m.requestStore.Get(ctx, string(requestID))
	if err != nil {
		return nil, err
	}

	if req.Status != types.AccessRequestStatusPending {
		return nil, errors.New("access: request is not pending")
	}

	if types.Now() > req.ExpiresAt {
		req.Status = types.AccessRequestStatusExpired
		_ = m.requestStore.Set(ctx, string(requestID), req)
		return nil, errors.New("access: request expired")
	}

	// Verify approver is in list if restricted
	if len(req.ApproverIDs) > 0 {
		isApprover := false
		for _, id := range req.ApproverIDs {
			if id == approverID {
				isApprover = true
				break
			}
		}
		if !isApprover {
			return nil, errors.New("access: not an authorized approver")
		}
	}

	// Prevent self-approval if requestor is approver
	if req.RequestorID == approverID && os.Getenv("SECRETR_ALLOW_SELF_APPROVAL") != "true" {
		return nil, errors.New("access: self-approval not allowed")
	}

	req.ApprovalCount++

	// For now, simpler logic: if ApprovalCount >= MinApprovals (default 1), approve it.
	minApprovals := req.MinApprovals
	if minApprovals <= 0 {
		minApprovals = 1
	}

	if req.ApprovalCount >= minApprovals {
		req.Status = types.AccessRequestStatusApproved

		// Parse duration
		duration, err := time.ParseDuration(req.Duration)
		if err != nil {
			// Default to 1 hour if invalid
			duration = 1 * time.Hour
		}

		// Create the actual grant
		grant, err := m.Grant(ctx, GrantOptions{
			GrantorID:    approverID,
			GranteeID:    req.RequestorID,
			ResourceID:   req.ResourceID,
			ResourceType: req.ResourceType,
			Scopes:       m.permissionsToScopes(req.Permissions), // Helper needed or assume simple mapping
			ExpiresIn:    duration,
			Conditions: &types.AccessConditions{
				RequireApproval: true,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("access: failed to grant access: %w", err)
		}

		req.AccessGrantID = &grant.ID
		req.ReviewerNotes = notes
	}

	req.UpdatedAt = types.Now()

	if err := m.requestStore.Set(ctx, string(requestID), req); err != nil {
		return nil, err
	}

	return req, nil
}

// permissionsToScopes is a helper (placeholder for now)
func (m *Manager) permissionsToScopes(permissions []string) []types.Scope {
	scopes := make([]types.Scope, len(permissions))
	for i, p := range permissions {
		scopes[i] = types.Scope(p)
	}
	return scopes
}

// DenyAccessRequest denies an access request
func (m *Manager) DenyAccessRequest(ctx context.Context, requestID types.ID, reviewerID types.ID, reason string) (*types.AccessRequest, error) {
	req, err := m.requestStore.Get(ctx, string(requestID))
	if err != nil {
		return nil, err
	}

	if req.Status != types.AccessRequestStatusPending {
		return nil, errors.New("access: request is not pending")
	}

	req.Status = types.AccessRequestStatusDenied
	req.ReviewerNotes = reason
	req.UpdatedAt = types.Now()

	if err := m.requestStore.Set(ctx, string(requestID), req); err != nil {
		return nil, err
	}

	return req, nil
}

// Grant creates an access grant
func (m *Manager) Grant(ctx context.Context, opts GrantOptions) (*types.AccessGrant, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	grant := &types.AccessGrant{
		ID:              id,
		GrantorID:       opts.GrantorID,
		GranteeID:       opts.GranteeID,
		ResourceID:      opts.ResourceID,
		ResourceType:    opts.ResourceType,
		Scopes:          types.NewScopeSet(opts.Scopes...),
		ScopeList:       opts.Scopes,
		Conditions:      opts.Conditions,
		CreatedAt:       now,
		ExpiresAt:       expiresAt,
		Status:          types.StatusActive,
		DelegationChain: opts.DelegationChain,
		Resharing:       opts.AllowResharing,
	}

	if err := m.grantStore.Set(ctx, string(id), grant); err != nil {
		return nil, err
	}

	return grant, nil
}

// GrantOptions holds grant creation options
type GrantOptions struct {
	GrantorID       types.ID
	GranteeID       types.ID
	ResourceID      types.ID
	ResourceType    string
	Scopes          []types.Scope
	Conditions      *types.AccessConditions
	ExpiresIn       time.Duration
	DelegationChain []types.ID
	AllowResharing  bool
}

// Check checks if an identity has access to a resource
func (m *Manager) Check(ctx context.Context, identityID types.ID, resourceID types.ID, requiredScopes []types.Scope) error {
	grants, err := m.grantStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, grant := range grants {
		if grant.GranteeID != identityID {
			continue
		}
		if grant.ResourceID != resourceID {
			continue
		}
		if grant.Status != types.StatusActive {
			continue
		}
		if grant.ExpiresAt != nil && types.Now() > *grant.ExpiresAt {
			continue
		}

		// Check if grant has all required scopes
		grant.Scopes = types.NewScopeSet(grant.ScopeList...)
		if grant.Scopes.HasAll(requiredScopes...) {
			// Check conditions
			if err := m.checkConditions(ctx, grant.Conditions); err != nil {
				continue
			}
			return nil // Access granted
		}
	}

	return ErrAccessDenied
}

func (m *Manager) checkConditions(ctx context.Context, conditions *types.AccessConditions) error {
	if conditions == nil {
		return nil
	}

	// Device check
	if len(conditions.DeviceIDs) > 0 {
		deviceID, ok := ctx.Value("device_id").(types.ID)
		if !ok || deviceID == "" {
			return errors.New("access: device ID required for this resource")
		}
		found := false
		for _, d := range conditions.DeviceIDs {
			if d == deviceID {
				found = true
				break
			}
		}
		if !found {
			return errors.New("access: device not in allowlist")
		}
	}

	// Time window check
	if len(conditions.TimeWindows) > 0 {
		now := time.Now()
		inWindow := false
		for _, tw := range conditions.TimeWindows {
			if m.isInTimeWindow(now, tw) {
				inWindow = true
				break
			}
		}
		if !inWindow {
			return errors.New("access: outside allowed time window")
		}
	}

	// IP range check
	if len(conditions.IPRanges) > 0 {
		clientIP, ok := ctx.Value("client_ip").(string)
		if !ok || clientIP == "" {
			return errors.New("access: client IP required for this resource")
		}
		if !m.isIPInRanges(clientIP, conditions.IPRanges) {
			return errors.New("access: IP not in allowed ranges")
		}
	}

	// MFA check
	if conditions.RequireMFA {
		mfaVerified, ok := ctx.Value("mfa_verified").(bool)
		if !ok || !mfaVerified {
			return errors.New("access: MFA verification required")
		}
	}

	// Approval check
	if conditions.RequireApproval {
		approved, ok := ctx.Value("access_approved").(bool)
		if !ok || !approved {
			return errors.New("access: approval required for this resource")
		}
	}

	return nil
}

// isInTimeWindow checks if a time is within a time window
func (m *Manager) isInTimeWindow(t time.Time, tw types.TimeWindow) bool {
	// Parse timezone
	loc := time.UTC
	if tw.Timezone != "" {
		if l, err := time.LoadLocation(tw.Timezone); err == nil {
			loc = l
		}
	}
	t = t.In(loc)

	// Check day of week
	if len(tw.Days) > 0 {
		dayMatch := false
		for _, d := range tw.Days {
			if int(t.Weekday()) == d {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}

	// Check time range
	if tw.StartTime != "" && tw.EndTime != "" {
		currentTime := t.Format("15:04")
		if currentTime < tw.StartTime || currentTime > tw.EndTime {
			return false
		}
	}

	return true
}

// isIPInRanges checks if an IP is in any of the allowed ranges
func (m *Manager) isIPInRanges(ip string, ranges []string) bool {
	for _, r := range ranges {
		// Simple exact match or CIDR match
		if r == ip {
			return true
		}
		// CIDR matching would require net.ParseCIDR
		// For now, support simple prefix matching
		if len(r) > 0 && r[len(r)-1] == '*' {
			prefix := r[:len(r)-1]
			if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// Revoke revokes an access grant
func (m *Manager) Revoke(ctx context.Context, grantID types.ID) error {
	grant, err := m.grantStore.Get(ctx, string(grantID))
	if err != nil {
		return ErrGrantNotFound
	}

	now := types.Now()
	grant.Status = types.StatusRevoked
	grant.RevokedAt = &now

	// Propagate revocation to delegated grants
	if err := m.propagateRevocation(ctx, grantID); err != nil {
		return err
	}

	return m.grantStore.Set(ctx, string(grantID), grant)
}

func (m *Manager) propagateRevocation(ctx context.Context, parentID types.ID) error {
	grants, err := m.grantStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, grant := range grants {
		for _, chainID := range grant.DelegationChain {
			if chainID == parentID {
				now := types.Now()
				grant.Status = types.StatusRevoked
				grant.RevokedAt = &now
				m.grantStore.Set(ctx, string(grant.ID), grant)
				break
			}
		}
	}

	return nil
}

// ListGrants lists grants for a grantee or resource
func (m *Manager) ListGrants(ctx context.Context, opts ListGrantsOptions) ([]*types.AccessGrant, error) {
	grants, err := m.grantStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := make([]*types.AccessGrant, 0)
	for _, grant := range grants {
		if opts.GranteeID != "" && grant.GranteeID != opts.GranteeID {
			continue
		}
		if opts.ResourceID != "" && grant.ResourceID != opts.ResourceID {
			continue
		}
		if !opts.IncludeRevoked && grant.Status == types.StatusRevoked {
			continue
		}
		grant.Scopes = types.NewScopeSet(grant.ScopeList...)
		result = append(result, grant)
	}

	return result, nil
}

// ListGrantsOptions holds list options
type ListGrantsOptions struct {
	GranteeID      types.ID
	ResourceID     types.ID
	IncludeRevoked bool
}

// Delegate creates a delegated grant
func (m *Manager) Delegate(ctx context.Context, originalGrantID types.ID, newGranteeID types.ID, scopes []types.Scope, delegatorID types.ID) (*types.AccessGrant, error) {
	original, err := m.grantStore.Get(ctx, string(originalGrantID))
	if err != nil {
		return nil, ErrGrantNotFound
	}

	if !original.Resharing {
		return nil, ErrDelegationDenied
	}

	if original.Status != types.StatusActive {
		return nil, ErrGrantRevoked
	}

	original.Scopes = types.NewScopeSet(original.ScopeList...)

	// Delegated scopes cannot exceed original scopes
	for _, scope := range scopes {
		if !original.Scopes.Has(scope) {
			return nil, fmt.Errorf("access: cannot delegate scope %s", scope)
		}
	}

	chain := append(original.DelegationChain, originalGrantID)

	return m.Grant(ctx, GrantOptions{
		GrantorID:       delegatorID,
		GranteeID:       newGranteeID,
		ResourceID:      original.ResourceID,
		ResourceType:    original.ResourceType,
		Scopes:          scopes,
		DelegationChain: chain,
		AllowResharing:  false, // Delegated grants cannot be reshared by default
	})
}

// Role management

// CreateRole creates a role
func (m *Manager) CreateRole(ctx context.Context, opts CreateRoleOptions) (*types.Role, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	role := &types.Role{
		ID:          id,
		Name:        opts.Name,
		Description: opts.Description,
		Scopes:      types.NewScopeSet(opts.Scopes...),
		ScopeList:   opts.Scopes,
		ParentID:    opts.ParentID,
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      types.StatusActive,
	}

	if err := m.roleStore.Set(ctx, string(id), role); err != nil {
		return nil, err
	}

	return role, nil
}

// CreateRoleOptions holds role creation options
type CreateRoleOptions struct {
	Name        string
	Description string
	Scopes      []types.Scope
	ParentID    *types.ID
}

// GetRole retrieves a role
func (m *Manager) GetRole(ctx context.Context, id types.ID) (*types.Role, error) {
	role, err := m.roleStore.Get(ctx, string(id))
	if err != nil {
		return nil, err
	}
	role.Scopes = types.NewScopeSet(role.ScopeList...)
	return role, nil
}

// ListRoles lists all roles
func (m *Manager) ListRoles(ctx context.Context) ([]*types.Role, error) {
	roles, err := m.roleStore.List(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		role.Scopes = types.NewScopeSet(role.ScopeList...)
	}
	return roles, nil
}

// DetectConflicts detects access conflicts
func (m *Manager) DetectConflicts(ctx context.Context, resourceID types.ID) ([]AccessConflict, error) {
	grants, err := m.ListGrants(ctx, ListGrantsOptions{ResourceID: resourceID})
	if err != nil {
		return nil, err
	}

	var conflicts []AccessConflict

	// Check for overlapping grants with different permissions
	for i, g1 := range grants {
		for j, g2 := range grants {
			if i >= j {
				continue
			}
			if g1.GranteeID == g2.GranteeID {
				// Same grantee, different grants - potential conflict
				if !scopesEqual(g1.ScopeList, g2.ScopeList) {
					conflicts = append(conflicts, AccessConflict{
						Grant1:      g1.ID,
						Grant2:      g2.ID,
						GranteeID:   g1.GranteeID,
						ResourceID:  resourceID,
						Description: "Conflicting scope definitions",
					})
				}
			}
		}
	}

	return conflicts, nil
}

// AccessConflict represents a detected access conflict
type AccessConflict struct {
	Grant1      types.ID
	Grant2      types.ID
	GranteeID   types.ID
	ResourceID  types.ID
	Description string
}

func scopesEqual(a, b []types.Scope) bool {
	if len(a) != len(b) {
		return false
	}
	setA := types.NewScopeSet(a...)
	for _, s := range b {
		if !setA.Has(s) {
			return false
		}
	}
	return true
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

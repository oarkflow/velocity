// Package org provides organization and team management functionality.
package org

import (
	"context"
	"errors"
	"fmt"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrOrgNotFound     = errors.New("org: organization not found")
	ErrOrgExists       = errors.New("org: organization already exists")
	ErrTeamNotFound    = errors.New("org: team not found")
	ErrTeamExists      = errors.New("org: team already exists")
	ErrEnvNotFound     = errors.New("org: environment not found")
	ErrEnvExists       = errors.New("org: environment already exists")
	ErrMemberNotFound  = errors.New("org: member not found")
	ErrMemberExists    = errors.New("org: member already exists")
	ErrAccessDenied    = errors.New("org: access denied")
	ErrLegalHoldActive = errors.New("org: legal hold is active, operation denied")
	ErrIncidentFrozen  = errors.New("org: organization is frozen due to incident")
)

// SessionRevoker is a callback to revoke sessions for an identity
type SessionRevoker func(ctx context.Context, identityID types.ID) error

// GrantRevoker is a callback to revoke all access grants for an identity
type GrantRevoker func(ctx context.Context, identityID types.ID) error

// ResourceTransferer is a callback to transfer owned resources to a new owner
type ResourceTransferer func(ctx context.Context, fromID, toID types.ID) error

// Manager handles organization and team operations
type Manager struct {
	store              *storage.Store
	crypto             *crypto.Engine
	orgStore           *storage.TypedStore[types.Organization]
	teamStore          *storage.TypedStore[types.Team]
	envStore           *storage.TypedStore[types.Environment]
	memberStore        *storage.TypedStore[OrgMember]
	transferStore      *storage.TypedStore[types.TransferWorkflow]
	sessionRevoker     SessionRevoker
	grantRevoker       GrantRevoker
	resourceTransferer ResourceTransferer
}

// OrgMember represents membership in an organization
type OrgMember struct {
	ID         types.ID           `json:"id"`
	OrgID      types.ID           `json:"org_id"`
	IdentityID types.ID           `json:"identity_id"`
	TeamID     *types.ID          `json:"team_id,omitempty"`
	Role       string             `json:"role"`                 // owner, admin, member, auditor, vendor, guest
	GuestType  string             `json:"guest_type,omitempty"` // auditor, vendor, contractor, temporary
	Scopes     types.ScopeSet     `json:"-"`
	ScopeList  []types.Scope      `json:"scopes"`
	InvitedBy  types.ID           `json:"invited_by"`
	InvitedAt  types.Timestamp    `json:"invited_at"`
	JoinedAt   *types.Timestamp   `json:"joined_at,omitempty"`
	ExpiresAt  *types.Timestamp   `json:"expires_at,omitempty"` // Auto-expiry for guest access
	RevokedAt  *types.Timestamp   `json:"revoked_at,omitempty"`
	Status     types.EntityStatus `json:"status"`
	Metadata   types.Metadata     `json:"metadata,omitempty"`
}

// ManagerConfig configures the organization manager
type ManagerConfig struct {
	Store              *storage.Store
	SessionRevoker     SessionRevoker
	GrantRevoker       GrantRevoker
	ResourceTransferer ResourceTransferer
}

// NewManager creates a new organization manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:              cfg.Store,
		crypto:             crypto.NewEngine(""),
		orgStore:           storage.NewTypedStore[types.Organization](cfg.Store, storage.CollectionOrganizations),
		teamStore:          storage.NewTypedStore[types.Team](cfg.Store, storage.CollectionTeams),
		envStore:           storage.NewTypedStore[types.Environment](cfg.Store, storage.CollectionEnvironments),
		memberStore:        storage.NewTypedStore[OrgMember](cfg.Store, "org_members"),
		transferStore:      storage.NewTypedStore[types.TransferWorkflow](cfg.Store, storage.CollectionTransfers),
		sessionRevoker:     cfg.SessionRevoker,
		grantRevoker:       cfg.GrantRevoker,
		resourceTransferer: cfg.ResourceTransferer,
	}
}

// CreateOrganization creates a new organization
func (m *Manager) CreateOrganization(ctx context.Context, opts CreateOrgOptions) (*types.Organization, error) {
	// Check if slug already exists
	existing, _ := m.GetOrganizationBySlug(ctx, opts.Slug)
	if existing != nil {
		return nil, ErrOrgExists
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	org := &types.Organization{
		ID:        id,
		Name:      opts.Name,
		Slug:      opts.Slug,
		OwnerID:   opts.OwnerID,
		CreatedAt: types.Now(),
		UpdatedAt: types.Now(),
		Status:    types.StatusActive,
		Settings: types.OrgSettings{
			RequireMFA:       opts.RequireMFA,
			SessionTimeout:   opts.SessionTimeoutMinutes,
			ComplianceMode:   opts.ComplianceMode,
			AllowedDomains:   opts.AllowedDomains,
			LegalHoldEnabled: false,
			IncidentFrozen:   false,
		},
		Metadata: opts.Metadata,
	}

	if err := m.orgStore.Set(ctx, string(org.ID), org); err != nil {
		return nil, err
	}

	// Add owner as first member
	ownerMember := &OrgMember{
		ID:         types.ID(fmt.Sprintf("%s-%s", org.ID, opts.OwnerID)),
		OrgID:      org.ID,
		IdentityID: opts.OwnerID,
		Role:       "owner",
		Scopes:     types.NewScopeSet(types.ScopeAdminAll),
		ScopeList:  []types.Scope{types.ScopeAdminAll},
		InvitedBy:  opts.OwnerID,
		InvitedAt:  types.Now(),
		Status:     types.StatusActive,
	}
	joinedAt := types.Now()
	ownerMember.JoinedAt = &joinedAt

	if err := m.memberStore.Set(ctx, string(ownerMember.ID), ownerMember); err != nil {
		return nil, err
	}

	// Create default environments
	for _, envName := range []string{"production", "staging", "development"} {
		if _, err := m.CreateEnvironment(ctx, CreateEnvOptions{
			OrgID:       org.ID,
			Name:        envName,
			Description: fmt.Sprintf("%s environment", envName),
			Protected:   envName == "production",
			CreatorID:   opts.OwnerID,
		}); err != nil {
			// Log but don't fail
			continue
		}
	}

	return org, nil
}

// CreateOrgOptions holds organization creation options
type CreateOrgOptions struct {
	Name                  string
	Slug                  string
	OwnerID               types.ID
	RequireMFA            bool
	SessionTimeoutMinutes int
	ComplianceMode        string
	AllowedDomains        []string
	Metadata              types.Metadata
}

// GetOrganization retrieves an organization by ID
func (m *Manager) GetOrganization(ctx context.Context, id types.ID) (*types.Organization, error) {
	org, err := m.orgStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrOrgNotFound
	}
	return org, nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (m *Manager) GetOrganizationBySlug(ctx context.Context, slug string) (*types.Organization, error) {
	orgs, err := m.orgStore.List(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if org.Slug == slug {
			return org, nil
		}
	}
	return nil, ErrOrgNotFound
}

// ListOrganizations lists all organizations
func (m *Manager) ListOrganizations(ctx context.Context) ([]*types.Organization, error) {
	return m.orgStore.List(ctx, "")
}

// UpdateOrganization updates an organization
func (m *Manager) UpdateOrganization(ctx context.Context, id types.ID, opts UpdateOrgOptions, updaterID types.ID) (*types.Organization, error) {
	org, err := m.GetOrganization(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if updater has permission
	if err := m.CheckPermission(ctx, id, updaterID, types.ScopeOrgUpdate); err != nil {
		return nil, err
	}

	if opts.Name != "" {
		org.Name = opts.Name
	}
	if opts.ComplianceMode != "" {
		org.Settings.ComplianceMode = opts.ComplianceMode
	}
	if opts.SessionTimeoutMinutes > 0 {
		org.Settings.SessionTimeout = opts.SessionTimeoutMinutes
	}
	org.Settings.RequireMFA = opts.RequireMFA
	org.UpdatedAt = types.Now()

	if err := m.orgStore.Set(ctx, string(org.ID), org); err != nil {
		return nil, err
	}

	return org, nil
}

// UpdateOrgOptions holds organization update options
type UpdateOrgOptions struct {
	Name                  string
	RequireMFA            bool
	SessionTimeoutMinutes int
	ComplianceMode        string
	AllowedDomains        []string
}

// DeleteOrganization deletes an organization
func (m *Manager) DeleteOrganization(ctx context.Context, id types.ID, deleterID types.ID) error {
	org, err := m.GetOrganization(ctx, id)
	if err != nil {
		return err
	}

	// Only owner can delete
	if org.OwnerID != deleterID {
		return ErrAccessDenied
	}

	// Check legal hold
	if org.Settings.LegalHoldEnabled {
		return ErrLegalHoldActive
	}

	org.Status = types.StatusRevoked
	org.UpdatedAt = types.Now()

	return m.orgStore.Set(ctx, string(org.ID), org)
}

// EnableLegalHold enables legal hold on an organization
func (m *Manager) EnableLegalHold(ctx context.Context, orgID types.ID, actorID types.ID) error {
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := m.CheckPermission(ctx, orgID, actorID, types.ScopeOrgLegalHold); err != nil {
		return err
	}

	org.Settings.LegalHoldEnabled = true
	org.UpdatedAt = types.Now()

	return m.orgStore.Set(ctx, string(org.ID), org)
}

// DisableLegalHold disables legal hold on an organization
func (m *Manager) DisableLegalHold(ctx context.Context, orgID types.ID, actorID types.ID) error {
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	// Only owner can disable legal hold
	if org.OwnerID != actorID {
		return ErrAccessDenied
	}

	org.Settings.LegalHoldEnabled = false
	org.UpdatedAt = types.Now()

	return m.orgStore.Set(ctx, string(org.ID), org)
}

// FreezeOrganization freezes the organization due to incident
func (m *Manager) FreezeOrganization(ctx context.Context, orgID types.ID, actorID types.ID) error {
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := m.CheckPermission(ctx, orgID, actorID, types.ScopeIncidentFreeze); err != nil {
		return err
	}

	org.Settings.IncidentFrozen = true
	org.UpdatedAt = types.Now()

	return m.orgStore.Set(ctx, string(org.ID), org)
}

// UnfreezeOrganization unfreezes the organization
func (m *Manager) UnfreezeOrganization(ctx context.Context, orgID types.ID, actorID types.ID) error {
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	// Only owner can unfreeze
	if org.OwnerID != actorID {
		return ErrAccessDenied
	}

	org.Settings.IncidentFrozen = false
	org.UpdatedAt = types.Now()

	return m.orgStore.Set(ctx, string(org.ID), org)
}

// Team Management

// CreateTeam creates a new team
func (m *Manager) CreateTeam(ctx context.Context, opts CreateTeamOptions) (*types.Team, error) {
	if err := m.CheckPermission(ctx, opts.OrgID, opts.CreatorID, types.ScopeOrgTeams); err != nil {
		return nil, err
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	team := &types.Team{
		ID:          id,
		OrgID:       opts.OrgID,
		Name:        opts.Name,
		Description: opts.Description,
		ParentID:    opts.ParentID,
		CreatedAt:   types.Now(),
		UpdatedAt:   types.Now(),
		Status:      types.StatusActive,
	}

	if err := m.teamStore.Set(ctx, string(team.ID), team); err != nil {
		return nil, err
	}

	return team, nil
}

// CreateTeamOptions holds team creation options
type CreateTeamOptions struct {
	OrgID       types.ID
	Name        string
	Description string
	ParentID    *types.ID
	CreatorID   types.ID
}

// GetTeam retrieves a team by ID
func (m *Manager) GetTeam(ctx context.Context, id types.ID) (*types.Team, error) {
	team, err := m.teamStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrTeamNotFound
	}
	return team, nil
}

// ListTeams lists teams in an organization
func (m *Manager) ListTeams(ctx context.Context, orgID types.ID) ([]*types.Team, error) {
	allTeams, err := m.teamStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var teams []*types.Team
	for _, t := range allTeams {
		if t.OrgID == orgID && t.Status == types.StatusActive {
			teams = append(teams, t)
		}
	}
	return teams, nil
}

// DeleteTeam deletes a team
func (m *Manager) DeleteTeam(ctx context.Context, id types.ID, deleterID types.ID) error {
	team, err := m.GetTeam(ctx, id)
	if err != nil {
		return err
	}

	if err := m.CheckPermission(ctx, team.OrgID, deleterID, types.ScopeOrgTeams); err != nil {
		return err
	}

	team.Status = types.StatusRevoked
	team.UpdatedAt = types.Now()

	return m.teamStore.Set(ctx, string(team.ID), team)
}

// Environment Management

// CreateEnvironment creates a new environment
func (m *Manager) CreateEnvironment(ctx context.Context, opts CreateEnvOptions) (*types.Environment, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	env := &types.Environment{
		ID:          id,
		OrgID:       opts.OrgID,
		Name:        opts.Name,
		Description: opts.Description,
		Protected:   opts.Protected,
		CreatedAt:   types.Now(),
		Status:      types.StatusActive,
	}

	if err := m.envStore.Set(ctx, string(env.ID), env); err != nil {
		return nil, err
	}

	return env, nil
}

// CreateEnvOptions holds environment creation options
type CreateEnvOptions struct {
	OrgID       types.ID
	Name        string
	Description string
	Protected   bool
	CreatorID   types.ID
}

// GetEnvironment retrieves an environment by ID
func (m *Manager) GetEnvironment(ctx context.Context, id types.ID) (*types.Environment, error) {
	env, err := m.envStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrEnvNotFound
	}
	return env, nil
}

// ListEnvironments lists environments in an organization
func (m *Manager) ListEnvironments(ctx context.Context, orgID types.ID) ([]*types.Environment, error) {
	allEnvs, err := m.envStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var envs []*types.Environment
	for _, e := range allEnvs {
		if e.OrgID == orgID && e.Status == types.StatusActive {
			envs = append(envs, e)
		}
	}
	return envs, nil
}

// Member Management

// InviteMember invites a member to the organization
func (m *Manager) InviteMember(ctx context.Context, opts InviteMemberOptions) (*OrgMember, error) {
	// Check if org is frozen
	org, err := m.GetOrganization(ctx, opts.OrgID)
	if err != nil {
		return nil, err
	}
	if org.Settings.IncidentFrozen {
		return nil, ErrIncidentFrozen
	}

	if err := m.CheckPermission(ctx, opts.OrgID, opts.InviterID, types.ScopeOrgInvite); err != nil {
		return nil, err
	}

	// Check if already a member
	existing, _ := m.GetMember(ctx, opts.OrgID, opts.IdentityID)
	if existing != nil && existing.Status == types.StatusActive {
		return nil, ErrMemberExists
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	member := &OrgMember{
		ID:         id,
		OrgID:      opts.OrgID,
		IdentityID: opts.IdentityID,
		TeamID:     opts.TeamID,
		Role:       opts.Role,
		Scopes:     types.NewScopeSet(opts.Scopes...),
		ScopeList:  opts.Scopes,
		InvitedBy:  opts.InviterID,
		InvitedAt:  types.Now(),
		Status:     types.StatusPending,
		Metadata:   opts.Metadata,
	}

	if err := m.memberStore.Set(ctx, string(member.ID), member); err != nil {
		return nil, err
	}

	return member, nil
}

// InviteMemberOptions holds member invitation options
type InviteMemberOptions struct {
	OrgID      types.ID
	IdentityID types.ID
	TeamID     *types.ID
	Role       string
	Scopes     []types.Scope
	InviterID  types.ID
	Metadata   types.Metadata
}

// AcceptInvitation accepts a membership invitation
func (m *Manager) AcceptInvitation(ctx context.Context, orgID types.ID, identityID types.ID) (*OrgMember, error) {
	member, err := m.GetMember(ctx, orgID, identityID)
	if err != nil {
		return nil, err
	}

	if member.Status != types.StatusPending {
		return nil, errors.New("org: invitation already processed")
	}

	member.Status = types.StatusActive
	joinedAt := types.Now()
	member.JoinedAt = &joinedAt

	if err := m.memberStore.Set(ctx, string(member.ID), member); err != nil {
		return nil, err
	}

	return member, nil
}

// GetMember retrieves a member by org and identity ID
func (m *Manager) GetMember(ctx context.Context, orgID types.ID, identityID types.ID) (*OrgMember, error) {
	members, err := m.memberStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, mem := range members {
		if mem.OrgID == orgID && mem.IdentityID == identityID {
			return mem, nil
		}
	}
	return nil, ErrMemberNotFound
}

// ListMembers lists members in an organization
func (m *Manager) ListMembers(ctx context.Context, orgID types.ID) ([]*OrgMember, error) {
	members, err := m.memberStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var orgMembers []*OrgMember
	for _, mem := range members {
		if mem.OrgID == orgID && mem.Status == types.StatusActive {
			orgMembers = append(orgMembers, mem)
		}
	}
	return orgMembers, nil
}

// RevokeMember revokes a member's access
func (m *Manager) RevokeMember(ctx context.Context, orgID types.ID, identityID types.ID, revokerID types.ID) error {
	// Check if org is frozen
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}
	if org.Settings.IncidentFrozen {
		return ErrIncidentFrozen
	}

	if err := m.CheckPermission(ctx, orgID, revokerID, types.ScopeOrgRevoke); err != nil {
		return err
	}

	member, err := m.GetMember(ctx, orgID, identityID)
	if err != nil {
		return err
	}

	// Cannot revoke owner
	if org.OwnerID == identityID {
		return errors.New("org: cannot revoke owner")
	}

	member.Status = types.StatusRevoked
	revokedAt := types.Now()
	member.RevokedAt = &revokedAt

	return m.memberStore.Set(ctx, string(member.ID), member)
}

// CheckPermission checks if an identity has a permission in an organization
func (m *Manager) CheckPermission(ctx context.Context, orgID types.ID, identityID types.ID, requiredScope types.Scope) error {
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	// Owner has all permissions
	if org.OwnerID == identityID {
		return nil
	}

	member, err := m.GetMember(ctx, orgID, identityID)
	if err != nil {
		return ErrAccessDenied
	}

	if member.Status != types.StatusActive {
		return ErrAccessDenied
	}

	// Rebuild scope set from list
	if member.Scopes == nil {
		member.Scopes = types.NewScopeSet(member.ScopeList...)
	}

	if !member.Scopes.Has(requiredScope) {
		return ErrAccessDenied
	}

	return nil
}

// Onboarding/Offboarding workflows

// OnboardMember handles member onboarding workflow
func (m *Manager) OnboardMember(ctx context.Context, opts OnboardOptions) error {
	org, err := m.GetOrganization(ctx, opts.OrgID)
	if err != nil {
		return err
	}

	if org.Settings.IncidentFrozen {
		return ErrIncidentFrozen
	}

	// Invite member
	member, err := m.InviteMember(ctx, InviteMemberOptions{
		OrgID:      opts.OrgID,
		IdentityID: opts.IdentityID,
		TeamID:     opts.TeamID,
		Role:       opts.Role,
		Scopes:     opts.Scopes,
		InviterID:  opts.OnboarderID,
		Metadata: types.Metadata{
			"onboarding":   true,
			"onboarded_by": string(opts.OnboarderID),
		},
	})
	if err != nil {
		return err
	}

	// Auto-accept for onboarding
	_, err = m.AcceptInvitation(ctx, opts.OrgID, member.IdentityID)
	return err
}

// OnboardOptions holds member onboarding options
type OnboardOptions struct {
	OrgID       types.ID
	IdentityID  types.ID
	TeamID      *types.ID
	Role        string
	Scopes      []types.Scope
	OnboarderID types.ID
}

// OffboardMember handles member offboarding workflow with lockdown
func (m *Manager) OffboardMember(ctx context.Context, orgID types.ID, identityID types.ID, offboarderID types.ID) error {
	if err := m.CheckPermission(ctx, orgID, offboarderID, types.ScopeOrgOffboard); err != nil {
		return err
	}

	// Get org to find owner for resource transfer
	org, err := m.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	// Revoke all sessions for this identity
	if m.sessionRevoker != nil {
		if err := m.sessionRevoker(ctx, identityID); err != nil {
			// Log but don't fail - session revocation is best effort
			_ = err
		}
	}

	// Revoke all access grants for this identity
	if m.grantRevoker != nil {
		if err := m.grantRevoker(ctx, identityID); err != nil {
			// Log but don't fail - grant revocation is best effort
			_ = err
		}
	}

	// Transfer ownership of resources to org owner if applicable
	if m.resourceTransferer != nil && org.OwnerID != identityID {
		if err := m.resourceTransferer(ctx, identityID, org.OwnerID); err != nil {
			// Log but don't fail - transfer is best effort
			_ = err
		}
	}

	// Revoke membership (do this last)
	if err := m.RevokeMember(ctx, orgID, identityID, offboarderID); err != nil {
		return err
	}

	return nil
}

// AuditorAccessOptions holds auditor access options
type AuditorAccessOptions struct {
	OrgID     types.ID
	AuditorID types.ID
	GranterID types.ID
	ExpiresAt *types.Timestamp
	Resources []types.ID // if empty, grants access to all
}

// GrantAuditorAccess grants read-only auditor access to an external auditor
func (m *Manager) GrantAuditorAccess(ctx context.Context, opts AuditorAccessOptions) (*OrgMember, error) {
	// Validate requester has org:auditor scope
	if err := m.CheckPermission(ctx, opts.OrgID, opts.GranterID, types.ScopeOrgAuditor); err != nil {
		return nil, err
	}

	// Create auditor scopes (read-only)
	auditorScopes := []types.Scope{
		types.ScopeAuditorRead,
		types.ScopeAuditorExport,
		types.ScopeSecretList,
		types.ScopeAuditQuery,
		types.ScopeAuditExport,
	}

	_, err := m.InviteMember(ctx, InviteMemberOptions{
		OrgID:      opts.OrgID,
		IdentityID: opts.AuditorID,
		Role:       "auditor",
		Scopes:     auditorScopes,
		InviterID:  opts.GranterID,
		Metadata: types.Metadata{
			"auditor":   true,
			"read_only": true,
			"resources": opts.Resources,
		},
	})
	if err != nil {
		return nil, err
	}

	// Auto-accept for auditor access
	return m.AcceptInvitation(ctx, opts.OrgID, opts.AuditorID)
}

// RevokeAuditorAccess revokes auditor access
func (m *Manager) RevokeAuditorAccess(ctx context.Context, orgID types.ID, auditorID types.ID, revokerID types.ID) error {
	if err := m.CheckPermission(ctx, orgID, revokerID, types.ScopeOrgAuditor); err != nil {
		return err
	}
	return m.RevokeMember(ctx, orgID, auditorID, revokerID)
}

// VendorAccessOptions holds vendor access options
type VendorAccessOptions struct {
	OrgID      types.ID
	VendorID   types.ID
	VendorName string
	GranterID  types.ID
	Resources  []types.ID
	Scopes     []types.Scope
	ExpiresIn  int64 // seconds
}

// CreateVendorAccess creates time-limited vendor access
func (m *Manager) CreateVendorAccess(ctx context.Context, opts VendorAccessOptions) (*types.VendorAccess, error) {
	if err := m.CheckPermission(ctx, opts.OrgID, opts.GranterID, types.ScopeVendorManage); err != nil {
		return nil, err
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(int64(now) + opts.ExpiresIn*1e9)
		expiresAt = &exp
	}

	// Default scopes for vendors
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []types.Scope{types.ScopeVendorLimited}
	}

	access := &types.VendorAccess{
		ID:         id,
		OrgID:      opts.OrgID,
		VendorID:   opts.VendorID,
		VendorName: opts.VendorName,
		Resources:  opts.Resources,
		Scopes:     types.NewScopeSet(scopes...),
		ScopeList:  scopes,
		ApprovedBy: opts.GranterID,
		ApprovedAt: now,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		Status:     types.StatusActive,
	}

	// Also add as org member with vendor role
	_, err = m.InviteMember(ctx, InviteMemberOptions{
		OrgID:      opts.OrgID,
		IdentityID: opts.VendorID,
		Role:       "vendor",
		Scopes:     scopes,
		InviterID:  opts.GranterID,
		Metadata: types.Metadata{
			"vendor":      true,
			"vendor_name": opts.VendorName,
			"resources":   opts.Resources,
		},
	})
	if err != nil && err != ErrMemberExists {
		return nil, err
	}

	return access, nil
}

// RevokeVendorAccess revokes vendor access
func (m *Manager) RevokeVendorAccess(ctx context.Context, orgID types.ID, vendorID types.ID, revokerID types.ID) error {
	if err := m.CheckPermission(ctx, orgID, revokerID, types.ScopeVendorManage); err != nil {
		return err
	}
	return m.RevokeMember(ctx, orgID, vendorID, revokerID)
}

// TransferOptions holds transfer initiation options
type TransferOptions struct {
	SourceOrgID       types.ID
	TargetOrgID       types.ID
	Resources         []types.ID
	InitiatorID       types.ID
	RequiredApprovals int
}

// InitiateTransfer starts an M&A transfer workflow
func (m *Manager) InitiateTransfer(ctx context.Context, opts TransferOptions) (*types.TransferWorkflow, error) {
	if err := m.CheckPermission(ctx, opts.SourceOrgID, opts.InitiatorID, types.ScopeTransferInit); err != nil {
		return nil, err
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	transfer := &types.TransferWorkflow{
		ID:                id,
		SourceOrgID:       opts.SourceOrgID,
		TargetOrgID:       opts.TargetOrgID,
		Status:            types.TransferStatusPending,
		Resources:         opts.Resources,
		InitiatedBy:       opts.InitiatorID,
		RequiredApprovals: opts.RequiredApprovals,
		ApprovedBy:        []types.ID{},
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := m.transferStore.Set(ctx, string(transfer.ID), transfer); err != nil {
		return nil, err
	}

	return transfer, nil
}

// GetTransfer retrieves a transfer workflow by ID
func (m *Manager) GetTransfer(ctx context.Context, id types.ID) (*types.TransferWorkflow, error) {
	return m.transferStore.Get(ctx, string(id))
}

// ApproveTransfer adds approval to a transfer workflow
func (m *Manager) ApproveTransfer(ctx context.Context, transfer *types.TransferWorkflow, approverID types.ID) error {
	// Check approver has permission in source org
	if err := m.CheckPermission(ctx, transfer.SourceOrgID, approverID, types.ScopeTransferApprove); err != nil {
		return err
	}

	// Check if already approved by this approver
	for _, id := range transfer.ApprovedBy {
		if id == approverID {
			return errors.New("org: already approved by this identity")
		}
	}

	transfer.ApprovedBy = append(transfer.ApprovedBy, approverID)
	transfer.UpdatedAt = types.Now()

	if len(transfer.ApprovedBy) >= transfer.RequiredApprovals {
		transfer.Status = types.TransferStatusApproved
	}

	return m.transferStore.Set(ctx, string(transfer.ID), transfer)
}

// ExecuteTransfer executes a transfer after all approvals
func (m *Manager) ExecuteTransfer(ctx context.Context, transfer *types.TransferWorkflow, executorID types.ID) error {
	if transfer.Status != types.TransferStatusApproved {
		return errors.New("org: transfer not approved")
	}

	if err := m.CheckPermission(ctx, transfer.SourceOrgID, executorID, types.ScopeTransferExecute); err != nil {
		return err
	}

	transfer.Status = types.TransferStatusInProgress
	transfer.UpdatedAt = types.Now()

	// The actual resource transfer would be handled by callbacks or external orchestration
	// For now, just mark as completed
	transfer.Status = types.TransferStatusCompleted
	now := types.Now()
	transfer.TransferredAt = &now

	return m.transferStore.Set(ctx, string(transfer.ID), transfer)
}

// GuestAccessOptions holds options for creating temporary guest access
type GuestAccessOptions struct {
	OrgID      types.ID
	IdentityID types.ID
	GuestType  string // auditor, vendor, contractor, temporary
	Role       string
	Scopes     []types.Scope
	GranterID  types.ID
	ExpiresIn  int64  // seconds - how long until access expires
	Reason     string // justification for access
}

// CreateGuestAccess creates time-limited guest access with automatic expiry
func (m *Manager) CreateGuestAccess(ctx context.Context, opts GuestAccessOptions) (*OrgMember, error) {
	// Check if org is frozen
	org, err := m.GetOrganization(ctx, opts.OrgID)
	if err != nil {
		return nil, err
	}
	if org.Settings.IncidentFrozen {
		return nil, ErrIncidentFrozen
	}

	if err := m.CheckPermission(ctx, opts.OrgID, opts.GranterID, types.ScopeOrgInvite); err != nil {
		return nil, err
	}

	// Check if already a member
	existing, _ := m.GetMember(ctx, opts.OrgID, opts.IdentityID)
	if existing != nil && existing.Status == types.StatusActive {
		return nil, ErrMemberExists
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(int64(now) + opts.ExpiresIn*1e9)
		expiresAt = &exp
	}

	// Default role if not specified
	role := opts.Role
	if role == "" {
		role = "guest"
	}

	member := &OrgMember{
		ID:         id,
		OrgID:      opts.OrgID,
		IdentityID: opts.IdentityID,
		Role:       role,
		GuestType:  opts.GuestType,
		Scopes:     types.NewScopeSet(opts.Scopes...),
		ScopeList:  opts.Scopes,
		InvitedBy:  opts.GranterID,
		InvitedAt:  now,
		JoinedAt:   &now, // Auto-accept for guest access
		ExpiresAt:  expiresAt,
		Status:     types.StatusActive,
		Metadata: types.Metadata{
			"guest":      true,
			"guest_type": opts.GuestType,
			"reason":     opts.Reason,
			"granted_by": string(opts.GranterID),
		},
	}

	if err := m.memberStore.Set(ctx, string(member.ID), member); err != nil {
		return nil, err
	}

	return member, nil
}

// CleanupExpiredGuests revokes access for all expired guest members
func (m *Manager) CleanupExpiredGuests(ctx context.Context) (int, error) {
	members, err := m.memberStore.List(ctx, "")
	if err != nil {
		return 0, err
	}

	now := types.Now()
	revokedCount := 0

	for _, member := range members {
		// Skip non-active members
		if member.Status != types.StatusActive {
			continue
		}

		// Check if member has expired
		if member.ExpiresAt != nil && *member.ExpiresAt < now {
			member.Status = types.StatusExpired
			revokedAt := now
			member.RevokedAt = &revokedAt
			member.Metadata["expired_automatically"] = true

			if err := m.memberStore.Set(ctx, string(member.ID), member); err != nil {
				// Log but continue with other members
				continue
			}

			// Revoke sessions for this identity
			if m.sessionRevoker != nil {
				_ = m.sessionRevoker(ctx, member.IdentityID)
			}

			// Revoke grants for this identity
			if m.grantRevoker != nil {
				_ = m.grantRevoker(ctx, member.IdentityID)
			}

			revokedCount++
		}
	}

	return revokedCount, nil
}

// ListExpiredGuests returns all expired guest members
func (m *Manager) ListExpiredGuests(ctx context.Context, orgID types.ID) ([]*OrgMember, error) {
	members, err := m.memberStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var expired []*OrgMember

	for _, member := range members {
		if member.OrgID != orgID {
			continue
		}
		if member.Status == types.StatusActive && member.ExpiresAt != nil && *member.ExpiresAt < now {
			expired = append(expired, member)
		}
	}

	return expired, nil
}

// ListActiveGuests returns all active guest members for an organization
func (m *Manager) ListActiveGuests(ctx context.Context, orgID types.ID) ([]*OrgMember, error) {
	members, err := m.memberStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	now := types.Now()
	var guests []*OrgMember

	for _, member := range members {
		if member.OrgID != orgID || member.Status != types.StatusActive {
			continue
		}
		// Check if it's a guest (has GuestType or Role is guest/auditor/vendor)
		isGuest := member.GuestType != "" ||
			member.Role == "guest" ||
			member.Role == "auditor" ||
			member.Role == "vendor"

		if isGuest {
			// Skip if expired
			if member.ExpiresAt != nil && *member.ExpiresAt < now {
				continue
			}
			guests = append(guests, member)
		}
	}

	return guests, nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

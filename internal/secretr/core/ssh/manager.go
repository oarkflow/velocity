// Package ssh provides SSH profile and session management functionality.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrProfileNotFound = errors.New("ssh: profile not found")
	ErrSessionNotFound = errors.New("ssh: session not found")
	ErrSessionActive   = errors.New("ssh: session is still active")
	ErrAccessDenied    = errors.New("ssh: access denied")
)

// CommandEntry represents an executed command in an SSH session
type CommandEntry struct {
	Timestamp  types.Timestamp `json:"timestamp"`
	Command    string          `json:"command"`
	ExitCode   int             `json:"exit_code"`
	Duration   time.Duration   `json:"duration_ns"`
}

// Manager handles SSH profile and session operations
type Manager struct {
	store        *storage.Store
	crypto       *crypto.Engine
	auditEngine  *audit.Engine
	profileStore *storage.TypedStore[types.SSHProfile]
	sessionStore *storage.TypedStore[types.SSHSession]
	commandStore *storage.TypedStore[CommandEntry]
}

// ManagerConfig configures the SSH manager
type ManagerConfig struct {
	Store       *storage.Store
	AuditEngine *audit.Engine
}

// NewManager creates a new SSH manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:        cfg.Store,
		crypto:       crypto.NewEngine(""),
		auditEngine:  cfg.AuditEngine,
		profileStore: storage.NewTypedStore[types.SSHProfile](cfg.Store, "ssh_profiles"),
		sessionStore: storage.NewTypedStore[types.SSHSession](cfg.Store, "ssh_sessions"),
		commandStore: storage.NewTypedStore[CommandEntry](cfg.Store, "ssh_commands"),
	}
}

// ProfileOptions holds SSH profile creation options
type ProfileOptions struct {
	Name          string
	Host          string
	Port          int
	User          string
	IdentityKeyID types.ID
	OwnerID       types.ID
	Options       types.Metadata
}

// CreateProfile creates a new SSH profile
func (m *Manager) CreateProfile(ctx context.Context, opts ProfileOptions) (*types.SSHProfile, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	port := opts.Port
	if port == 0 {
		port = 22
	}

	now := types.Now()
	profile := &types.SSHProfile{
		ID:            id,
		Name:          opts.Name,
		Host:          opts.Host,
		Port:          port,
		User:          opts.User,
		IdentityKeyID: opts.IdentityKeyID,
		OwnerID:       opts.OwnerID,
		Options:       opts.Options,
		CreatedAt:     now,
		UpdatedAt:     now,
		Status:        types.StatusActive,
	}

	if err := m.profileStore.Set(ctx, string(id), profile); err != nil {
		return nil, err
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "ssh",
			Action:       "profile_create",
			ActorID:      opts.OwnerID,
			ActorType:    "identity",
			ResourceID:   &id,
			ResourceType: "ssh_profile",
			Success:      true,
			Details: types.Metadata{
				"host": opts.Host,
				"user": opts.User,
			},
		})
	}

	return profile, nil
}

// GetProfile retrieves an SSH profile by ID
func (m *Manager) GetProfile(ctx context.Context, id types.ID) (*types.SSHProfile, error) {
	profile, err := m.profileStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrProfileNotFound
	}
	return profile, nil
}

// ListProfiles lists SSH profiles for an owner
func (m *Manager) ListProfiles(ctx context.Context, ownerID types.ID) ([]*types.SSHProfile, error) {
	all, err := m.profileStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var profiles []*types.SSHProfile
	for _, p := range all {
		if p.OwnerID == ownerID && p.Status == types.StatusActive {
			profiles = append(profiles, p)
		}
	}
	return profiles, nil
}

// UpdateProfile updates an SSH profile
func (m *Manager) UpdateProfile(ctx context.Context, id types.ID, opts ProfileOptions) (*types.SSHProfile, error) {
	profile, err := m.GetProfile(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check ownership
	if profile.OwnerID != opts.OwnerID {
		return nil, ErrAccessDenied
	}

	if opts.Name != "" {
		profile.Name = opts.Name
	}
	if opts.Host != "" {
		profile.Host = opts.Host
	}
	if opts.Port != 0 {
		profile.Port = opts.Port
	}
	if opts.User != "" {
		profile.User = opts.User
	}
	if opts.IdentityKeyID != "" {
		profile.IdentityKeyID = opts.IdentityKeyID
	}
	if opts.Options != nil {
		profile.Options = opts.Options
	}
	profile.UpdatedAt = types.Now()

	if err := m.profileStore.Set(ctx, string(id), profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// DeleteProfile deletes an SSH profile
func (m *Manager) DeleteProfile(ctx context.Context, id types.ID, ownerID types.ID) error {
	profile, err := m.GetProfile(ctx, id)
	if err != nil {
		return err
	}

	if profile.OwnerID != ownerID {
		return ErrAccessDenied
	}

	profile.Status = types.StatusRevoked
	profile.UpdatedAt = types.Now()

	return m.profileStore.Set(ctx, string(id), profile)
}

// StartSession starts a new SSH session
func (m *Manager) StartSession(ctx context.Context, profileID types.ID, identityID types.ID) (*types.SSHSession, error) {
	profile, err := m.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}

	// Check access (owner only for now)
	if profile.OwnerID != identityID {
		return nil, ErrAccessDenied
	}

	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	session := &types.SSHSession{
		ID:           id,
		ProfileID:    profileID,
		IdentityID:   identityID,
		StartedAt:    types.Now(),
		Status:       "active",
		CommandCount: 0,
		Metadata: types.Metadata{
			"host": profile.Host,
			"user": profile.User,
		},
	}

	if err := m.sessionStore.Set(ctx, string(id), session); err != nil {
		return nil, err
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "ssh",
			Action:       "session_start",
			ActorID:      identityID,
			ActorType:    "identity",
			ResourceID:   &id,
			ResourceType: "ssh_session",
			Success:      true,
			Details: types.Metadata{
				"profile_id": string(profileID),
				"host":       profile.Host,
			},
		})
	}

	return session, nil
}

// GetSession retrieves an SSH session
func (m *Manager) GetSession(ctx context.Context, id types.ID) (*types.SSHSession, error) {
	session, err := m.sessionStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

// ListSessions lists SSH sessions for an identity
func (m *Manager) ListSessions(ctx context.Context, identityID types.ID, activeOnly bool) ([]*types.SSHSession, error) {
	all, err := m.sessionStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var sessions []*types.SSHSession
	for _, s := range all {
		if s.IdentityID == identityID {
			if activeOnly && s.Status != "active" {
				continue
			}
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

// EndSession ends an SSH session
func (m *Manager) EndSession(ctx context.Context, sessionID types.ID) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.Status != "active" {
		return ErrSessionActive
	}

	now := types.Now()
	session.EndedAt = &now
	session.Status = "ended"

	if err := m.sessionStore.Set(ctx, string(sessionID), session); err != nil {
		return err
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "ssh",
			Action:       "session_end",
			ActorID:      session.IdentityID,
			ActorType:    "identity",
			ResourceID:   &sessionID,
			ResourceType: "ssh_session",
			Success:      true,
			Details: types.Metadata{
				"command_count": session.CommandCount,
			},
		})
	}

	return nil
}

// RecordCommand records a command executed in an SSH session
func (m *Manager) RecordCommand(ctx context.Context, sessionID types.ID, command string, exitCode int, duration time.Duration) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.Status != "active" {
		return ErrSessionActive
	}

	entry := &CommandEntry{
		Timestamp: types.Now(),
		Command:   command,
		ExitCode:  exitCode,
		Duration:  duration,
	}

	entryID := string(sessionID) + "_" + fmt.Sprintf("%d", entry.Timestamp)
	if err := m.commandStore.Set(ctx, entryID, entry); err != nil {
		return err
	}

	session.CommandCount++
	return m.sessionStore.Set(ctx, string(sessionID), session)
}

// GetSessionCommands retrieves commands for a session
func (m *Manager) GetSessionCommands(ctx context.Context, sessionID types.ID) ([]*CommandEntry, error) {
	all, err := m.commandStore.List(ctx, string(sessionID))
	if err != nil {
		return nil, err
	}
	return all, nil
}

// TerminateSession forcefully terminates an SSH session
func (m *Manager) TerminateSession(ctx context.Context, sessionID types.ID, terminatorID types.ID) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	now := types.Now()
	session.EndedAt = &now
	session.Status = "terminated"
	session.Metadata["terminated_by"] = string(terminatorID)

	if err := m.sessionStore.Set(ctx, string(sessionID), session); err != nil {
		return err
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "ssh",
			Action:       "session_terminate",
			ActorID:      terminatorID,
			ActorType:    "identity",
			ResourceID:   &sessionID,
			ResourceType: "ssh_session",
			Success:      true,
		})
	}

	return nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

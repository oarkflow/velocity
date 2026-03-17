// Package incident provides incident response functionality.
package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrIncidentNotFound    = errors.New("incident: not found")
	ErrIncidentExists      = errors.New("incident: already exists")
	ErrAccessDenied        = errors.New("incident: access denied")
	ErrIncidentResolved    = errors.New("incident: already resolved")
	ErrNoActiveIncident    = errors.New("incident: no active incident")
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// OrgFreezer is a callback to freeze an organization
type OrgFreezer func(ctx context.Context, orgID types.ID, actorID types.ID) error

// SecretRotator is a callback to rotate secrets
type SecretRotator func(ctx context.Context, orgID types.ID, scope string) error

// KeyRotator is a callback to rotate keys
type KeyRotator func(ctx context.Context, orgID types.ID, scope string) error

// AccessGranter is a callback to create emergency access grants
type AccessGranter func(ctx context.Context, grantorID, granteeID, resourceID types.ID, scopes []types.Scope, duration time.Duration) error

// Manager handles incident response operations
type Manager struct {
	store         *storage.Store
	crypto        *crypto.Engine
	auditEngine   *audit.Engine
	incidentStore *storage.TypedStore[types.Incident]
	signerKey     []byte
	orgFreezer    OrgFreezer
	secretRotator SecretRotator
	keyRotator    KeyRotator
	accessGranter AccessGranter
}

// ManagerConfig configures the incident manager
type ManagerConfig struct {
	Store         *storage.Store
	AuditEngine   *audit.Engine
	SignerKey     []byte
	OrgFreezer    OrgFreezer
	SecretRotator SecretRotator
	KeyRotator    KeyRotator
	AccessGranter AccessGranter
}

// NewManager creates a new incident manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:         cfg.Store,
		crypto:        crypto.NewEngine(""),
		auditEngine:   cfg.AuditEngine,
		incidentStore: storage.NewTypedStore[types.Incident](cfg.Store, storage.CollectionIncidents),
		signerKey:     cfg.SignerKey,
		orgFreezer:    cfg.OrgFreezer,
		secretRotator: cfg.SecretRotator,
		keyRotator:    cfg.KeyRotator,
		accessGranter: cfg.AccessGranter,
	}
}

// DeclareIncident declares a new security incident
func (m *Manager) DeclareIncident(ctx context.Context, opts DeclareOptions) (*types.Incident, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	incident := &types.Incident{
		ID:          id,
		OrgID:       opts.OrgID,
		Type:        opts.Type,
		Severity:    opts.Severity,
		DeclaredBy:  opts.DeclaredBy,
		DeclaredAt:  types.Now(),
		Status:      types.StatusActive,
		Description: opts.Description,
		Timeline: []types.IncidentEvent{
			{
				Timestamp:   types.Now(),
				ActorID:     opts.DeclaredBy,
				Action:      "declared",
				Description: fmt.Sprintf("Incident declared with severity: %s", opts.Severity),
			},
		},
	}

	if err := m.incidentStore.Set(ctx, string(incident.ID), incident); err != nil {
		return nil, err
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "declare",
			ActorID:      opts.DeclaredBy,
			ActorType:    "identity",
			ResourceID:   &incident.ID,
			ResourceType: "incident",
			Success:      true,
			Details: types.Metadata{
				"severity":    opts.Severity,
				"type":        opts.Type,
				"description": opts.Description,
			},
		})
	}

	return incident, nil
}

// DeclareOptions holds incident declaration options
type DeclareOptions struct {
	OrgID       types.ID
	Type        string
	Severity    string
	Description string
	DeclaredBy  types.ID
}

// GetIncident retrieves an incident by ID
func (m *Manager) GetIncident(ctx context.Context, id types.ID) (*types.Incident, error) {
	incident, err := m.incidentStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrIncidentNotFound
	}
	return incident, nil
}

// GetActiveIncident returns the current active incident for an organization
func (m *Manager) GetActiveIncident(ctx context.Context, orgID types.ID) (*types.Incident, error) {
	incidents, err := m.incidentStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, inc := range incidents {
		if inc.OrgID == orgID && inc.Status == types.StatusActive {
			return inc, nil
		}
	}
	return nil, ErrNoActiveIncident
}

// ListIncidents lists incidents for an organization
func (m *Manager) ListIncidents(ctx context.Context, orgID types.ID) ([]*types.Incident, error) {
	incidents, err := m.incidentStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var orgIncidents []*types.Incident
	for _, inc := range incidents {
		if inc.OrgID == orgID {
			orgIncidents = append(orgIncidents, inc)
		}
	}
	return orgIncidents, nil
}

// AddTimelineEvent adds an event to the incident timeline
func (m *Manager) AddTimelineEvent(ctx context.Context, incidentID types.ID, event types.IncidentEvent) error {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return err
	}

	if incident.Status != types.StatusActive {
		return ErrIncidentResolved
	}

	event.Timestamp = types.Now()
	incident.Timeline = append(incident.Timeline, event)

	return m.incidentStore.Set(ctx, string(incident.ID), incident)
}

// FreezeAccess freezes all access for the organization
func (m *Manager) FreezeAccess(ctx context.Context, incidentID types.ID, actorID types.ID) error {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return err
	}

	if incident.Status != types.StatusActive {
		return ErrIncidentResolved
	}

	// Add timeline event
	event := types.IncidentEvent{
		Timestamp:   types.Now(),
		ActorID:     actorID,
		Action:      "freeze_access",
		Description: "Organization-wide access freeze initiated",
	}
	incident.Timeline = append(incident.Timeline, event)

	if err := m.incidentStore.Set(ctx, string(incident.ID), incident); err != nil {
		return err
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "freeze_access",
			ActorID:      actorID,
			ActorType:    "identity",
			ResourceID:   &incidentID,
			ResourceType: "incident",
			Success:      true,
		})
	}

	// Trigger actual access freeze via org manager
	if m.orgFreezer != nil {
		if err := m.orgFreezer(ctx, incident.OrgID, actorID); err != nil {
			return fmt.Errorf("incident: failed to freeze organization: %w", err)
		}
	}

	return nil
}

// EmergencyRotation triggers emergency rotation of secrets/keys
func (m *Manager) EmergencyRotation(ctx context.Context, incidentID types.ID, opts RotationOptions) error {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return err
	}

	if incident.Status != types.StatusActive {
		return ErrIncidentResolved
	}

	// Add timeline event
	event := types.IncidentEvent{
		Timestamp:   types.Now(),
		ActorID:     opts.ActorID,
		Action:      "emergency_rotation",
		Description: fmt.Sprintf("Emergency rotation initiated: %s", opts.RotationType),
	}
	incident.Timeline = append(incident.Timeline, event)

	if err := m.incidentStore.Set(ctx, string(incident.ID), incident); err != nil {
		return err
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "emergency_rotation",
			ActorID:      opts.ActorID,
			ActorType:    "identity",
			ResourceID:   &incidentID,
			ResourceType: "incident",
			Success:      true,
			Details: types.Metadata{
				"rotation_type": opts.RotationType,
				"scope":         opts.Scope,
			},
		})
	}

	// Trigger actual rotation via keys/secrets managers
	switch opts.RotationType {
	case "secrets", "all":
		if m.secretRotator != nil {
			if err := m.secretRotator(ctx, incident.OrgID, opts.Scope); err != nil {
				return fmt.Errorf("incident: secret rotation failed: %w", err)
			}
		}
		if opts.RotationType == "secrets" {
			break
		}
		fallthrough
	case "keys":
		if m.keyRotator != nil {
			if err := m.keyRotator(ctx, incident.OrgID, opts.Scope); err != nil {
				return fmt.Errorf("incident: key rotation failed: %w", err)
			}
		}
	}

	return nil
}

// RotationOptions holds emergency rotation options
type RotationOptions struct {
	ActorID      types.ID
	RotationType string // "secrets", "keys", "all"
	Scope        string // "all", specific resource pattern
}

// EmergencyAccessGrant grants emergency access
func (m *Manager) EmergencyAccessGrant(ctx context.Context, incidentID types.ID, opts EmergencyAccessOptions) error {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return err
	}

	if incident.Status != types.StatusActive {
		return ErrIncidentResolved
	}

	// Add timeline event
	event := types.IncidentEvent{
		Timestamp:   types.Now(),
		ActorID:     opts.GrantorID,
		Action:      "emergency_access_grant",
		Description: fmt.Sprintf("Emergency access granted to %s for %s", opts.GranteeID, opts.ResourceID),
	}
	incident.Timeline = append(incident.Timeline, event)

	if err := m.incidentStore.Set(ctx, string(incident.ID), incident); err != nil {
		return err
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "emergency_access_grant",
			ActorID:      opts.GrantorID,
			ActorType:    "identity",
			ResourceID:   &incidentID,
			ResourceType: "incident",
			Success:      true,
			Details: types.Metadata{
				"grantee_id":  string(opts.GranteeID),
				"resource_id": string(opts.ResourceID),
				"duration":    opts.Duration.String(),
			},
		})
	}

	// Create actual access grant via access manager
	if m.accessGranter != nil {
		if err := m.accessGranter(ctx, opts.GrantorID, opts.GranteeID, opts.ResourceID, opts.Scopes, opts.Duration); err != nil {
			return fmt.Errorf("incident: failed to create emergency access grant: %w", err)
		}
	}

	return nil
}

// EmergencyAccessOptions holds emergency access options
type EmergencyAccessOptions struct {
	GrantorID  types.ID
	GranteeID  types.ID
	ResourceID types.ID
	Scopes     []types.Scope
	Duration   time.Duration
	Reason     string
}

// ResolveIncident resolves an incident
func (m *Manager) ResolveIncident(ctx context.Context, incidentID types.ID, resolverID types.ID, resolution string) error {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return err
	}

	if incident.Status != types.StatusActive {
		return ErrIncidentResolved
	}

	// Add timeline event
	event := types.IncidentEvent{
		Timestamp:   types.Now(),
		ActorID:     resolverID,
		Action:      "resolved",
		Description: resolution,
	}
	incident.Timeline = append(incident.Timeline, event)

	resolvedAt := types.Now()
	incident.ResolvedAt = &resolvedAt
	incident.Status = types.StatusExpired // Using Expired to indicate resolved

	if err := m.incidentStore.Set(ctx, string(incident.ID), incident); err != nil {
		return err
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "resolve",
			ActorID:      resolverID,
			ActorType:    "identity",
			ResourceID:   &incidentID,
			ResourceType: "incident",
			Success:      true,
			Details: types.Metadata{
				"resolution": resolution,
			},
		})
	}

	return nil
}

// GetTimeline returns the incident timeline
func (m *Manager) GetTimeline(ctx context.Context, incidentID types.ID) ([]types.IncidentEvent, error) {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	return incident.Timeline, nil
}

// ReconstructTimeline reconstructs the incident timeline from audit logs
func (m *Manager) ReconstructTimeline(ctx context.Context, incidentID types.ID, startTime, endTime time.Time) ([]types.IncidentEvent, error) {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, err
	}

	// Get audit events for the incident period
	var events []types.IncidentEvent

	if m.auditEngine != nil {
		auditEvents, err := m.auditEngine.Query(ctx, audit.QueryOptions{
			StartTime: startTime,
			EndTime:   endTime,
			Limit:     1000,
		})
		if err != nil {
			return nil, err
		}

		// Convert audit events to incident timeline events
		for _, ae := range auditEvents {
			events = append(events, types.IncidentEvent{
				Timestamp:   ae.Timestamp,
				ActorID:     ae.ActorID,
				Action:      ae.Action,
				Description: fmt.Sprintf("[%s] %s on %s", ae.Type, ae.Action, ae.ResourceType),
			})
		}
	}

	// Merge with existing timeline
	events = append(events, incident.Timeline...)

	return events, nil
}

// EvidenceExport represents exported incident evidence
type EvidenceExport struct {
	IncidentID  types.ID              `json:"incident_id"`
	Incident    *types.Incident       `json:"incident"`
	AuditEvents []*types.AuditEvent   `json:"audit_events,omitempty"`
	ExportedAt  time.Time             `json:"exported_at"`
	ExportedBy  types.ID              `json:"exported_by"`
	Signature   []byte                `json:"signature,omitempty"`
}

// ExportEvidence exports incident evidence for external review
func (m *Manager) ExportEvidence(ctx context.Context, incidentID types.ID, exporterID types.ID) ([]byte, error) {
	incident, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, err
	}

	export := EvidenceExport{
		IncidentID: incidentID,
		Incident:   incident,
		ExportedAt: time.Now(),
		ExportedBy: exporterID,
	}

	// Get related audit events
	if m.auditEngine != nil && incident.DeclaredAt > 0 {
		startTime := incident.DeclaredAt.Time()
		endTime := time.Now()
		if incident.ResolvedAt != nil {
			endTime = incident.ResolvedAt.Time()
		}

		auditEvents, _ := m.auditEngine.Query(ctx, audit.QueryOptions{
			StartTime: startTime,
			EndTime:   endTime,
			Limit:     10000,
		})
		export.AuditEvents = auditEvents
	}

	// Add attached evidence
	for _, evidenceID := range incident.Evidence {
		// Audit events are already retrieved above via the query
		_ = evidenceID // Evidence IDs stored for reference
	}

	data, err := json.Marshal(export)
	if err != nil {
		return nil, err
	}

	// Sign the export
	if len(m.signerKey) > 0 {
		sig, err := m.crypto.Sign(m.signerKey, data)
		if err != nil {
			return nil, err
		}
		export.Signature = sig
		data, _ = json.Marshal(export)
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "export_evidence",
			ActorID:      exporterID,
			ActorType:    "identity",
			ResourceID:   &incidentID,
			ResourceType: "incident",
			Success:      true,
		})
	}

	return data, nil
}

// AttestationReport represents a post-incident attestation
type AttestationReport struct {
	IncidentID     types.ID   `json:"incident_id"`
	ReportID       types.ID   `json:"report_id"`
	Summary        string     `json:"summary"`
	RootCause      string     `json:"root_cause"`
	ActionsToken   []string   `json:"actions_taken"`
	Remediation    []string   `json:"remediation_steps"`
	CreatedAt      time.Time  `json:"created_at"`
	CreatedBy      types.ID   `json:"created_by"`
	Signature      []byte     `json:"signature,omitempty"`
}

// GenerateAttestationReport generates a post-incident attestation report
func (m *Manager) GenerateAttestationReport(ctx context.Context, opts AttestationOptions) (*AttestationReport, error) {
	incident, err := m.GetIncident(ctx, opts.IncidentID)
	if err != nil {
		return nil, err
	}

	if incident.Status == types.StatusActive {
		return nil, errors.New("incident: cannot create attestation for active incident")
	}

	reportID, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	report := &AttestationReport{
		IncidentID:   opts.IncidentID,
		ReportID:     reportID,
		Summary:      opts.Summary,
		RootCause:    opts.RootCause,
		ActionsToken: opts.ActionsTaken,
		Remediation:  opts.Remediation,
		CreatedAt:    time.Now(),
		CreatedBy:    opts.AuthorID,
	}

	// Sign if key available
	if len(m.signerKey) > 0 {
		data, _ := json.Marshal(report)
		sig, _ := m.crypto.Sign(m.signerKey, data)
		report.Signature = sig
	}

	// Log to audit
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "incident",
			Action:       "attestation_report",
			ActorID:      opts.AuthorID,
			ActorType:    "identity",
			ResourceID:   &opts.IncidentID,
			ResourceType: "incident",
			Success:      true,
		})
	}

	return report, nil
}

// AttestationOptions holds attestation report options
type AttestationOptions struct {
	IncidentID   types.ID
	Summary      string
	RootCause    string
	ActionsTaken []string
	Remediation  []string
	AuthorID     types.ID
}

// MonitorActivity provides live activity monitoring during an incident
func (m *Manager) MonitorActivity(ctx context.Context, incidentID types.ID, since time.Time) ([]*types.AuditEvent, error) {
	_, err := m.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, err
	}

	if m.auditEngine == nil {
		return nil, errors.New("incident: audit engine not configured")
	}

	return m.auditEngine.Query(ctx, audit.QueryOptions{
		StartTime: since,
		EndTime:   time.Now(),
		Limit:     100,
	})
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

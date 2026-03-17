package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// BreachIncident represents a security breach incident.
type BreachIncident struct {
	IncidentID     string                `json:"incident_id"`
	DetectedAt     time.Time             `json:"detected_at"`
	ReportedAt     *time.Time            `json:"reported_at,omitempty"`
	Severity       string                `json:"severity"`
	Description    string                `json:"description"`
	Frameworks     []ComplianceFramework `json:"frameworks"`
	AffectedCount  int                   `json:"affected_count"`
	Status         string                `json:"status"` // detected, reported, resolved
	ReportDeadline time.Time             `json:"report_deadline"`
}

// ReportIncident records a breach incident.
func (bns *BreachNotificationSystem) ReportIncident(ctx context.Context, incident *BreachIncident) error {
	if incident.IncidentID == "" {
		incident.IncidentID = fmt.Sprintf("breach:%d", time.Now().UnixNano())
	}
	if incident.DetectedAt.IsZero() {
		incident.DetectedAt = time.Now()
	}
	if incident.ReportDeadline.IsZero() {
		// GDPR Art. 33 - 72 hours
		incident.ReportDeadline = incident.DetectedAt.Add(72 * time.Hour)
	}
	if incident.Status == "" {
		incident.Status = "detected"
	}

	data, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("failed to marshal breach incident: %w", err)
	}

	key := []byte("breach:incident:" + incident.IncidentID)
	return bns.db.Put(key, data)
}

// MarkReported updates incident status to reported.
func (bns *BreachNotificationSystem) MarkReported(ctx context.Context, incidentID string) error {
	incident, err := bns.getIncident(incidentID)
	if err != nil {
		return err
	}

	now := time.Now()
	incident.Status = "reported"
	incident.ReportedAt = &now

	data, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("failed to marshal breach incident: %w", err)
	}

	key := []byte("breach:incident:" + incident.IncidentID)
	return bns.db.Put(key, data)
}

// ListIncidents retrieves all breach incidents.
func (bns *BreachNotificationSystem) ListIncidents(ctx context.Context) ([]BreachIncident, error) {
	keys, err := bns.db.Keys("breach:incident:*")
	if err != nil {
		return nil, err
	}

	incidents := make([]BreachIncident, 0)
	for _, key := range keys {
		data, err := bns.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var incident BreachIncident
		if err := json.Unmarshal(data, &incident); err != nil {
			continue
		}
		incidents = append(incidents, incident)
	}

	return incidents, nil
}

func (bns *BreachNotificationSystem) getIncident(incidentID string) (*BreachIncident, error) {
	data, err := bns.db.Get([]byte("breach:incident:" + incidentID))
	if err != nil {
		return nil, fmt.Errorf("breach incident not found: %w", err)
	}
	var incident BreachIncident
	if err := json.Unmarshal(data, &incident); err != nil {
		return nil, fmt.Errorf("failed to unmarshal breach incident: %w", err)
	}
	return &incident, nil
}

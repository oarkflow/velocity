package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// TopicComplianceBreach is a compliance-plugin-local event topic (not one
// of api's well-known Topic* constants), published whenever RecordBreach
// is called, so other plugins (e.g. notifications, once built) can react.
const TopicComplianceBreach = "compliance.breach"

// BreachRecord is a persisted breach notification obligation. NotifyBy
// hardcodes the GDPR Article 33 72-hour notification deadline, ported
// directly from v1's breach_notification.go.
type BreachRecord struct {
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
	NotifyBy    time.Time `json:"notify_by"`
}

// RecordBreach is an extension beyond api.ComplianceService: not every
// deployment needs breach tracking as part of the core interface, but the
// plugin exposes it for callers that type-assert to *compliance.Plugin
// (or look it up via the registry and assert to an interface with this
// method).
func (p *Plugin) RecordBreach(ctx context.Context, description string) (BreachRecord, error) {
	if p.storage == nil {
		return BreachRecord{}, fmt.Errorf("%w: cannot record breach", errNotInitialized)
	}

	now := time.Now()
	rec := BreachRecord{
		Description: description,
		DetectedAt:  now,
		NotifyBy:    now.Add(72 * time.Hour), // GDPR Art. 33
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return BreachRecord{}, fmt.Errorf("compliance: marshal breach record: %w", err)
	}
	key := fmt.Sprintf("compliance/breach/%d", now.UnixNano())
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(key), Value: data}); err != nil {
		return BreachRecord{}, fmt.Errorf("compliance: persisting breach record: %w", err)
	}

	if p.bus != nil {
		p.bus.Publish(ctx, api.Event{Topic: TopicComplianceBreach, Source: p.Name(), Payload: rec})
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "breach.recorded",
		Resource: description,
		Detail:   map[string]any{"notify_by": rec.NotifyBy},
	})
	return rec, nil
}

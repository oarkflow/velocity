package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

type retentionRecord struct {
	AppliedAt        time.Time `json:"applied_at"`
	Action           string    `json:"action"` // "archived" or "skipped-legal-hold"
	SkippedLegalHold bool      `json:"skipped_legal_hold"`
}

type consentRecord struct {
	Granted    bool      `json:"granted"`
	RecordedAt time.Time `json:"recorded_at"`
}

// hasLegalHold reports whether resource currently has an active legal
// hold, set via SetLegalHold.
func (p *Plugin) hasLegalHold(ctx context.Context, resource string) (bool, error) {
	data, ok, err := p.storage.Get(ctx, []byte(legalHoldKey(resource)))
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return string(data) == "true", nil
}

// SetLegalHold is an admin-facing extension beyond api.ComplianceService
// (ported from v1's legal-hold gating in retention_manager.go): it must be
// checked before ApplyRetention is allowed to actually archive/delete a
// resource.
func (p *Plugin) SetLegalHold(ctx context.Context, resource string, hold bool) error {
	if p.storage == nil {
		return errNotInitialized
	}
	val := "false"
	if hold {
		val = "true"
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(legalHoldKey(resource)), Value: []byte(val)}); err != nil {
		return fmt.Errorf("compliance: setting legal hold for %q: %w", resource, err)
	}
	return nil
}

// ApplyRetention applies the retention manager's action to resource: if
// resource is under an active legal hold, retention is skipped (recorded
// as such, not silently ignored); otherwise the resource is marked
// archived. Ported from v1's retention_manager.go, ported correctly:
// unlike v1's gdpr_retention.go wrapper, this returns a real error rather
// than nil when the storage backend isn't wired.
func (p *Plugin) ApplyRetention(ctx context.Context, resource string) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot apply retention for %q", errNotInitialized, resource)
	}

	held, err := p.hasLegalHold(ctx, resource)
	if err != nil {
		return fmt.Errorf("compliance: checking legal hold for %q: %w", resource, err)
	}

	rec := retentionRecord{AppliedAt: time.Now()}
	if held {
		rec.Action = "skipped-legal-hold"
		rec.SkippedLegalHold = true
	} else {
		rec.Action = "archived"
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("compliance: marshal retention record for %q: %w", resource, err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(retentionKey(resource)), Value: data}); err != nil {
		return fmt.Errorf("compliance: persisting retention record for %q: %w", resource, err)
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "retention." + rec.Action,
		Resource: resource,
	})
	return nil
}

// RecordConsent persists a GDPR consent decision. This is the direct fix
// for v1's bug: v1's GDPRController.GrantConsent/WithdrawConsent returned
// nil (success) whenever gc.consentMgr was nil, so a caller had no way to
// tell "recorded" from "silently ignored". Here, an uninitialized plugin
// returns errNotInitialized instead.
func (p *Plugin) RecordConsent(ctx context.Context, subject, purpose string, granted bool) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot record consent for subject %q purpose %q", errNotInitialized, subject, purpose)
	}

	rec := consentRecord{Granted: granted, RecordedAt: time.Now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("compliance: marshal consent record: %w", err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(consentKey(subject, purpose)), Value: data}); err != nil {
		return fmt.Errorf("compliance: persisting consent for subject %q purpose %q: %w", subject, purpose, err)
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    subject,
		Action:   "consent.recorded",
		Resource: purpose,
		Detail:   map[string]any{"granted": granted},
	})
	return nil
}

// HasConsent is an internal query helper beyond api.ComplianceService,
// mirroring v1's GDPRController.HasActiveConsent — but, like
// RecordConsent, it errors rather than silently reporting "no consent" if
// uninitialized.
func (p *Plugin) HasConsent(ctx context.Context, subject, purpose string) (bool, error) {
	if p.storage == nil {
		return false, fmt.Errorf("%w: cannot check consent for subject %q purpose %q", errNotInitialized, subject, purpose)
	}
	data, ok, err := p.storage.Get(ctx, []byte(consentKey(subject, purpose)))
	if err != nil {
		return false, fmt.Errorf("compliance: reading consent for subject %q purpose %q: %w", subject, purpose, err)
	}
	if !ok {
		return false, nil
	}
	var rec consentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return false, fmt.Errorf("compliance: decoding consent record for subject %q purpose %q: %w", subject, purpose, err)
	}
	return rec.Granted, nil
}

// Anonymize actually rewrites the stored value at the given resource key
// (looked up directly on the shared storage backend) to a masked form,
// ported (simplified) from v1's data_masking.go strategies. Unlike a
// stub, this really overwrites the data in place — Anonymize is not
// satisfied by merely logging intent.
func (p *Plugin) Anonymize(ctx context.Context, resource string) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot anonymize %q", errNotInitialized, resource)
	}

	data, ok, err := p.storage.Get(ctx, []byte(resource))
	if err != nil {
		return fmt.Errorf("compliance: reading %q for anonymization: %w", resource, err)
	}
	if !ok {
		return fmt.Errorf("compliance: cannot anonymize %q: resource not found", resource)
	}

	masked := maskValue(string(data))
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(resource), Value: []byte(masked)}); err != nil {
		return fmt.Errorf("compliance: writing anonymized value for %q: %w", resource, err)
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "anonymize",
		Resource: resource,
	})
	return nil
}

// maskValue applies v1's data_masking.go "full" strategy (replace every
// character with '*'). Regex-based partial masking keyed by data
// classification (v1's MaskingRule/DataMaskingEngine) is a natural
// follow-up once field-level classification metadata is threaded through
// the resource key scheme; this pass ports the strategy function itself
// so it's ready to wire up.
func maskValue(v string) string {
	if v == "" {
		return v
	}
	return strings.Repeat("*", len(v))
}

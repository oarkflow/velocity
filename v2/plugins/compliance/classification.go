package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// SetClassification persists resource's managed classification level.
// This is deliberately simpler than v1's DataClassificationEngine (which
// auto-detects PII/PHI/PCI via regex scanners on write) — it is the
// "operator or caller explicitly sets a classification" half of that
// system, ported as a real, tested capability; auto-detection is a
// larger, separate follow-up.
func (p *Plugin) SetClassification(ctx context.Context, resource, level string) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot set classification for %q", errNotInitialized, resource)
	}

	rec := api.ClassificationRecord{Resource: resource, Level: level, SetAt: time.Now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("compliance: marshal classification record for %q: %w", resource, err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(classificationKey(resource)), Value: data}); err != nil {
		return fmt.Errorf("compliance: persisting classification for %q: %w", resource, err)
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "classification.set",
		Resource: resource,
		Detail:   map[string]any{"level": level},
	})
	return nil
}

// GetClassification returns resource's currently managed classification,
// or a zero-value ClassificationRecord with an error if none was ever
// set — matching this plugin's rule of erroring rather than returning a
// misleadingly empty success.
func (p *Plugin) GetClassification(ctx context.Context, resource string) (api.ClassificationRecord, error) {
	if p.storage == nil {
		return api.ClassificationRecord{}, fmt.Errorf("%w: cannot get classification for %q", errNotInitialized, resource)
	}
	data, ok, err := p.storage.Get(ctx, []byte(classificationKey(resource)))
	if err != nil {
		return api.ClassificationRecord{}, fmt.Errorf("compliance: reading classification for %q: %w", resource, err)
	}
	if !ok {
		return api.ClassificationRecord{}, fmt.Errorf("compliance: no classification set for %q", resource)
	}
	var rec api.ClassificationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return api.ClassificationRecord{}, fmt.Errorf("compliance: decoding classification for %q: %w", resource, err)
	}
	return rec, nil
}

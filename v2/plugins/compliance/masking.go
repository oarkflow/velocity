package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// applyMaskStrategy ports v1's data_masking.go applyMaskStrategy exactly:
// full replaces every character with '*', partial keeps the last 4
// characters visible (or fully masks values of 4 or fewer characters),
// and anything else (including MaskRedact) replaces the whole value with
// "[REDACTED]".
func applyMaskStrategy(value string, strategy api.MaskStrategy) string {
	switch strategy {
	case api.MaskFull:
		return strings.Repeat("*", len(value))
	case api.MaskPartial:
		if len(value) <= 4 {
			return strings.Repeat("*", len(value))
		}
		return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
	default: // api.MaskRedact and anything unrecognized
		return "[REDACTED]"
	}
}

// MaskWithStrategy is Anonymize's configurable sibling: Anonymize always
// applies MaskFull (kept unchanged for backward compatibility with
// existing callers); MaskWithStrategy lets a caller choose full, partial,
// or redact, matching v1's selectable DataMaskingEngine strategies.
func (p *Plugin) MaskWithStrategy(ctx context.Context, resource string, strategy api.MaskStrategy) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot mask %q", errNotInitialized, resource)
	}

	data, ok, err := p.storage.Get(ctx, []byte(resource))
	if err != nil {
		return fmt.Errorf("compliance: reading %q for masking: %w", resource, err)
	}
	if !ok {
		return fmt.Errorf("compliance: cannot mask %q: resource not found", resource)
	}

	masked := applyMaskStrategy(string(data), strategy)
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(resource), Value: []byte(masked)}); err != nil {
		return fmt.Errorf("compliance: writing masked value for %q: %w", resource, err)
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "mask",
		Resource: resource,
		Detail:   map[string]any{"strategy": string(strategy)},
	})
	return nil
}

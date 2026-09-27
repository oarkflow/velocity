package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// RecordLineage appends ev to resource's lifecycle history, ported from
// v1's data_lineage.go LineageManager.RecordEvent. Events are keyed by a
// zero-padded nanosecond timestamp so GetLineage's Scan naturally returns
// them in chronological order.
func (p *Plugin) RecordLineage(ctx context.Context, ev api.LineageEvent) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot record lineage for %q", errNotInitialized, ev.Resource)
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("compliance: marshal lineage event for %q: %w", ev.Resource, err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(lineageKey(ev.Resource, ev.At)), Value: data}); err != nil {
		return fmt.Errorf("compliance: persisting lineage event for %q: %w", ev.Resource, err)
	}
	return nil
}

// GetLineage returns resource's lineage events in the order recorded.
func (p *Plugin) GetLineage(ctx context.Context, resource string) ([]api.LineageEvent, error) {
	if p.storage == nil {
		return nil, fmt.Errorf("%w: cannot get lineage for %q", errNotInitialized, resource)
	}
	it, err := p.storage.Scan(ctx, []byte(lineagePrefix(resource)))
	if err != nil {
		return nil, fmt.Errorf("compliance: scanning lineage for %q: %w", resource, err)
	}
	defer it.Close()

	var events []api.LineageEvent
	for it.Next() {
		var ev api.LineageEvent
		if err := json.Unmarshal(it.Value(), &ev); err != nil {
			return nil, fmt.Errorf("compliance: decoding lineage event for %q: %w", resource, err)
		}
		events = append(events, ev)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("compliance: iterating lineage for %q: %w", resource, err)
	}
	return events, nil
}

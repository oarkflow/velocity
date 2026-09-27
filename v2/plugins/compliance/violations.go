package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// violationSeq is a monotonic disambiguator for same-timestamp violations,
// shared across every Plugin instance in the process. It MUST be mutated
// only via sync/atomic — a concurrency stress test caught a real data race
// here (plain "violationSeq++" from concurrent Evaluate calls landing in
// recordViolation).
var violationSeq uint64

// recordViolation persists a Violation for a denied Evaluate call and
// attempts a rate-limited webhook delivery if one is configured. Ported
// (simplified — no ResolvedAt/TicketID/SOC-escalation bookkeeping) from
// v1's violations.go ComplianceViolation/ViolationsManager. Errors here
// are logged, not returned/propagated: Evaluate's caller already has its
// PolicyDecision and must not be blocked or failed by a bookkeeping
// problem in a side channel.
func (p *Plugin) recordViolation(ctx context.Context, rule, resource, severity string) {
	if p.storage == nil {
		return
	}
	seq := atomic.AddUint64(&violationSeq, 1)
	v := api.Violation{
		ID:       fmt.Sprintf("v-%d", seq),
		Rule:     rule,
		Resource: resource,
		Severity: severity,
		At:       time.Now(),
	}
	data, err := json.Marshal(v)
	if err != nil {
		if p.log != nil {
			p.log.Error("compliance: marshal violation", "err", err)
		}
		return
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(violationKey(resource, v.At, seq)), Value: data}); err != nil {
		if p.log != nil {
			p.log.Error("compliance: persisting violation", "err", err)
		}
		return
	}

	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "violation.recorded",
		Resource: resource,
		Detail:   map[string]any{"rule": rule, "severity": severity},
	})

	p.maybeDeliverWebhook(ctx, v)
}

// maybeDeliverWebhook sends v to the configured violation_webhook_url,
// subject to a sliding-one-minute-window rate limit
// (violation_webhook_rate_limit, default 60/min, <=0 meaning unlimited) —
// ported from v1 violations.go's intent of not hammering an alert target
// under a flood of violations. Deliveries beyond the limit are dropped
// (not queued/retried) and logged as such; the Violation itself is always
// persisted and queryable via ListViolations regardless of whether the
// webhook fired.
func (p *Plugin) maybeDeliverWebhook(ctx context.Context, v api.Violation) {
	if p.violationWebhookURL == "" {
		return
	}
	if !p.allowWebhookDelivery() {
		if p.log != nil {
			p.log.Warn("compliance: violation webhook rate limit exceeded, dropping delivery", "violation_id", v.ID)
		}
		return
	}

	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.violationWebhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := p.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if p.log != nil {
			p.log.Error("compliance: violation webhook delivery failed", "violation_id", v.ID, "err", err)
		}
		return
	}
	resp.Body.Close()
}

// allowWebhookDelivery implements a sliding one-minute-window rate
// limiter: it prunes timestamps older than a minute, then allows the
// call only if fewer than violationRateLimit deliveries remain in the
// window (recording this one if so).
func (p *Plugin) allowWebhookDelivery() bool {
	if p.violationRateLimit <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)

	p.rateMu.Lock()
	defer p.rateMu.Unlock()

	kept := p.rateWindow[:0]
	for _, t := range p.rateWindow {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	p.rateWindow = kept

	if len(p.rateWindow) >= p.violationRateLimit {
		return false
	}
	p.rateWindow = append(p.rateWindow, now)
	return true
}

// ListViolations returns recorded Violations for resource in the order
// recorded, or every violation across all resources if resource is "".
func (p *Plugin) ListViolations(ctx context.Context, resource string) ([]api.Violation, error) {
	if p.storage == nil {
		return nil, fmt.Errorf("%w: cannot list violations", errNotInitialized)
	}
	it, err := p.storage.Scan(ctx, []byte(violationResourcePrefix(resource)))
	if err != nil {
		return nil, fmt.Errorf("compliance: scanning violations: %w", err)
	}
	defer it.Close()

	var out []api.Violation
	for it.Next() {
		var v api.Violation
		if err := json.Unmarshal(it.Value(), &v); err != nil {
			return nil, fmt.Errorf("compliance: decoding violation: %w", err)
		}
		out = append(out, v)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("compliance: iterating violations: %w", err)
	}
	return out, nil
}

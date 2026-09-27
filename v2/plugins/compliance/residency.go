package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// SetResidencyRule persists rule, replacing any existing rule for the
// same ResourcePrefix. Ported from v1's data_residency.go
// DataResidencyManager.AddPolicy (simplified: no PolicyID/Framework/
// Enabled bookkeeping — a rule present under a prefix is always active;
// removing residency enforcement for a prefix means not setting a rule,
// or overwriting it with an empty Region, your caller's choice).
func (p *Plugin) SetResidencyRule(ctx context.Context, rule api.ResidencyRule) error {
	if p.storage == nil {
		return fmt.Errorf("%w: cannot set residency rule for prefix %q", errNotInitialized, rule.ResourcePrefix)
	}
	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("compliance: marshal residency rule for %q: %w", rule.ResourcePrefix, err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(residencyRuleKey(rule.ResourcePrefix)), Value: data}); err != nil {
		return fmt.Errorf("compliance: persisting residency rule for %q: %w", rule.ResourcePrefix, err)
	}
	_ = p.Record(ctx, api.AuditEvent{
		Actor:    "compliance",
		Action:   "residency.rule_set",
		Resource: rule.ResourcePrefix,
		Detail:   map[string]any{"region": rule.Region},
	})
	return nil
}

// CheckResidency reports whether currentRegion is allowed for resource
// under whichever residency rule (if any) matches by longest
// ResourcePrefix. No matching rule means residency is unconstrained for
// resource, so (true, "", nil) is returned — mirroring v1's
// ValidateResidency, which allows any region when no policy covers a
// path. A matching rule that disagrees with currentRegion returns
// (false, reason, nil) — this is an expected, common outcome for callers
// to branch on, not an operational error.
func (p *Plugin) CheckResidency(ctx context.Context, resource, currentRegion string) (bool, string, error) {
	if p.storage == nil {
		return false, "", fmt.Errorf("%w: cannot check residency for %q", errNotInitialized, resource)
	}

	it, err := p.storage.Scan(ctx, []byte(residencyRulePrefix))
	if err != nil {
		return false, "", fmt.Errorf("compliance: scanning residency rules: %w", err)
	}
	defer it.Close()

	var best api.ResidencyRule
	haveMatch := false
	for it.Next() {
		var rule api.ResidencyRule
		if err := json.Unmarshal(it.Value(), &rule); err != nil {
			continue
		}
		if !strings.HasPrefix(resource, rule.ResourcePrefix) {
			continue
		}
		if !haveMatch || len(rule.ResourcePrefix) > len(best.ResourcePrefix) {
			best = rule
			haveMatch = true
		}
	}
	if err := it.Err(); err != nil {
		return false, "", fmt.Errorf("compliance: iterating residency rules: %w", err)
	}
	if !haveMatch {
		return true, "", nil
	}
	if strings.EqualFold(best.Region, currentRegion) {
		return true, "", nil
	}
	reason := fmt.Sprintf("resource %q is restricted to region %q by residency rule for prefix %q, but current region is %q", resource, best.Region, best.ResourcePrefix, currentRegion)
	return false, reason, nil
}

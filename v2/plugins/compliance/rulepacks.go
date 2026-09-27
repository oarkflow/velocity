package compliance

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// rulePackEntry is the JSON schema ImportRulePack accepts, e.g.:
//
//	{"rules": [
//	  {"classification": "restricted", "action": "delete", "requireRole": "admin", "reason": "...", "severity": "critical"}
//	]}
//
// classification maps to Rule.MinLevel via classLevel (unknown/empty
// classification means MinLevel 0, i.e. applies to every classification);
// action (optional) maps to a single-entry Rule.Actions (empty means "any
// action", matching Rule's own zero-value semantics). This is a smaller,
// data-only alternative to v1's policy_rule_packs.go named GDPR/HIPAA/PCI
// presets — those presets carry no portable content of their own (they're
// v1-specific policy text), so this pass ports the general import
// mechanism rather than inventing new preset content; a caller wanting a
// "GDPR pack" today builds its own rulePackEntry JSON and imports it.
type rulePackEntry struct {
	Classification string `json:"classification"`
	Action         string `json:"action"`
	RequireRole    string `json:"requireRole"`
	Reason         string `json:"reason"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
}

type rulePack struct {
	Rules []rulePackEntry `json:"rules"`
}

// ImportRulePack decodes packJSON and appends its rules to the same
// PolicyEngine.Evaluate rule set loadRules built at Init — imported rules
// take effect immediately and are additive (they never remove existing
// rules). A malformed pack, or one containing no rules, is an error
// rather than a silent no-op.
func (p *Plugin) ImportRulePack(ctx context.Context, packJSON []byte) error {
	var pack rulePack
	if err := json.Unmarshal(packJSON, &pack); err != nil {
		return fmt.Errorf("compliance: decoding rule pack: %w", err)
	}
	if len(pack.Rules) == 0 {
		return fmt.Errorf("compliance: rule pack contains no rules")
	}

	newRules := make([]Rule, 0, len(pack.Rules))
	for i, e := range pack.Rules {
		if e.RequireRole == "" {
			return fmt.Errorf("compliance: rule pack entry %d: requireRole is required (a rule with no required role can never deny anything)", i)
		}
		r := Rule{
			MinLevel:    classLevel(e.Classification),
			RequireRole: e.RequireRole,
			Reason:      e.Reason,
			Name:        e.Name,
			Severity:    e.Severity,
		}
		if e.Action != "" {
			r.Actions = []string{e.Action}
		}
		if r.Reason == "" {
			r.Reason = fmt.Sprintf("imported rule pack entry %d denied this request", i)
		}
		newRules = append(newRules, r)
	}

	p.rulesMu.Lock()
	p.rules = append(p.rules, newRules...)
	p.rulesMu.Unlock()

	_ = p.Record(ctx, api.AuditEvent{
		Actor:  "compliance",
		Action: "rulepack.imported",
		Detail: map[string]any{"rules_added": len(newRules)},
	})
	return nil
}

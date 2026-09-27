package compliance

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// Rule is one classification-based access rule, ported (simplified) from
// v1's policy_engine.go + violations.go rule/policy model.
type Rule struct {
	// MinLevel is the minimum classification level (see classLevels) this
	// rule applies to; classifications below this level never match.
	MinLevel int
	// Actions restricts the rule to specific actions; empty means "any
	// action".
	Actions []string
	// RequireRole is the role the subject must hold for the rule to
	// allow the request; if the subject lacks it, the rule denies.
	RequireRole string
	Reason      string
	// Name identifies the rule for Violation.Rule; defaults to Reason if
	// empty (set explicitly by ImportRulePack for imported rules).
	Name string
	// Severity classifies a Violation recorded from this rule's denial
	// ("critical", "high", "medium", "low"); defaults to "medium".
	Severity string
}

// classLevels mirrors v1's policy_engine.go dataClassValue ordering
// (public < internal < confidential < restricted), used so a single rule
// set applies uniformly across KV/Object/Secret regardless of resource
// type.
var classLevels = map[string]int{
	"public":       1,
	"internal":     2,
	"confidential": 3,
	"restricted":   4,
}

func classLevel(classification string) int {
	if v, ok := classLevels[classification]; ok {
		return v
	}
	return 0
}

// defaultRules is the built-in rule set used when the manifest doesn't
// configure any (v1 required an operator to author policies explicitly;
// this default set gives a v2 deployment a real, non-empty starting
// policy instead of allowing everything by default).
func defaultRules() []Rule {
	return []Rule{
		{
			MinLevel:    classLevels["restricted"],
			RequireRole: "admin",
			Reason:      "restricted-classification resources require the admin role",
			Name:        "default.restricted-requires-admin",
			Severity:    "critical",
		},
		{
			MinLevel:    classLevels["confidential"],
			Actions:     []string{"delete", "export"},
			RequireRole: "admin",
			Reason:      "delete/export of confidential-or-higher classification data requires the admin role",
			Name:        "default.confidential-delete-export-requires-admin",
			Severity:    "high",
		},
	}
}

// loadRules returns the configured rule set, falling back to
// defaultRules(). Config-driven custom rules are a natural follow-up
// (parsing cfg.Raw()["rules"]); left as defaults-only for this pass so the
// engine has real, testable behavior without requiring config wiring.
func loadRules(cfg api.PluginConfig) []Rule {
	_ = cfg
	return defaultRules()
}

func hasRole(subject api.Principal, role string) bool {
	for _, r := range subject.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func actionMatches(actions []string, action string) bool {
	if len(actions) == 0 {
		return true
	}
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

// Evaluate checks subject/action/resource/classification against the
// plugin's rule set and returns the first denial found, or an allow if no
// rule denies the request.
func (p *Plugin) Evaluate(ctx context.Context, subject api.Principal, action, resource, classification string) (api.PolicyDecision, error) {
	level := classLevel(classification)

	p.rulesMu.RLock()
	rules := make([]Rule, len(p.rules))
	copy(rules, p.rules)
	p.rulesMu.RUnlock()

	for _, rule := range rules {
		if level < rule.MinLevel {
			continue
		}
		if !actionMatches(rule.Actions, action) {
			continue
		}
		if rule.RequireRole != "" && !hasRole(subject, rule.RequireRole) {
			name := rule.Name
			if name == "" {
				name = rule.Reason
			}
			severity := rule.Severity
			if severity == "" {
				severity = "medium"
			}
			// Evaluate must still return the decision synchronously even
			// if recording/alerting the violation fails — a denial is
			// always honored regardless of whether its side-channel
			// bookkeeping succeeds.
			p.recordViolation(ctx, name, resource, severity)
			return api.PolicyDecision{Allowed: false, Reason: rule.Reason}, nil
		}
	}
	return api.PolicyDecision{Allowed: true, Reason: "no policy rule denied this request"}, nil
}

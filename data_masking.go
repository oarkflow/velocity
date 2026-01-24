package velocity

import (
	"fmt"
	"regexp"
	"strings"
)

// MaskingRule defines a masking rule for sensitive fields.
type MaskingRule struct {
	RuleID    string             `json:"rule_id"`
	Pattern   *regexp.Regexp     `json:"-"`
	PatternStr string            `json:"pattern"`
	Strategy  string             `json:"strategy"` // full, partial, redact
	DataClass DataClassification `json:"data_class"`
}

// DataMaskingEngine masks content based on rules.
type DataMaskingEngine struct {
	rules []*MaskingRule
}

// NewDataMaskingEngine creates a new masking engine.
func NewDataMaskingEngine() *DataMaskingEngine {
	return &DataMaskingEngine{rules: make([]*MaskingRule, 0)}
}

// AddRule adds a masking rule.
func (dme *DataMaskingEngine) AddRule(rule *MaskingRule) error {
	if rule.Pattern == nil && rule.PatternStr != "" {
		compiled, err := regexp.Compile(rule.PatternStr)
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		rule.Pattern = compiled
	}
	dme.rules = append(dme.rules, rule)
	return nil
}

// MaskString masks data using matching rules.
func (dme *DataMaskingEngine) MaskString(data string, class DataClassification) string {
	masked := data
	for _, rule := range dme.rules {
		if rule.DataClass != "" && rule.DataClass != class {
			continue
		}
		if rule.Pattern != nil {
			masked = rule.Pattern.ReplaceAllStringFunc(masked, func(match string) string {
				return applyMaskStrategy(match, rule.Strategy)
			})
		}
	}
	return masked
}

func applyMaskStrategy(value, strategy string) string {
	switch strategy {
	case "full":
		return strings.Repeat("*", len(value))
	case "partial":
		if len(value) <= 4 {
			return strings.Repeat("*", len(value))
		}
		return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
	default:
		return "[REDACTED]"
	}
}

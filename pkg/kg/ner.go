package kg

import (
	"regexp"
	"strings"
	"sync"
)

// KGNEREngine extracts named entities from text.
type KGNEREngine interface {
	Extract(text string) []KGEntity
}

type nerRule struct {
	Type       string
	Pattern    *regexp.Regexp
	PatternRaw string
	Confidence float64
	Normalize  func(string) string
}

// RuleBasedNER uses compiled regex patterns for entity extraction.
type RuleBasedNER struct {
	rules []nerRule
	mu    sync.RWMutex
}

func NewRuleBasedNER() *RuleBasedNER {
	n := &RuleBasedNER{}
	n.initDefaultRules()
	return n
}

func (n *RuleBasedNER) initDefaultRules() {
	n.rules = []nerRule{
		{
			Type:       "EMAIL",
			Pattern:    regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			PatternRaw: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Confidence: 0.95,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "URL",
			Pattern:    regexp.MustCompile(`https?://[^\s<>"'` + "`" + `\)]+`),
			PatternRaw: `https?://[^\s<>"'\)]+`,
			Confidence: 0.95,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "DOMAIN",
			Pattern:    regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`),
			PatternRaw: `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "IP_ADDRESS",
			Pattern:    regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			PatternRaw: `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
			Confidence: 0.85,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`),
			PatternRaw: `\b\d{4}-\d{2}-\d{2}\b`,
			Confidence: 0.95,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b\d{1,2}/\d{1,2}/\d{2,4}\b`),
			PatternRaw: `\b\d{1,2}/\d{1,2}/\d{2,4}\b`,
			Confidence: 0.80,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`),
			PatternRaw: `\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`,
			Confidence: 0.90,
		},
		{
			Type:       "MONEY",
			Pattern:    regexp.MustCompile(`\$[\d,]+(?:\.\d{2})?`),
			PatternRaw: `\$[\d,]+(?:\.\d{2})?`,
			Confidence: 0.90,
		},
		{
			Type:       "MONEY",
			Pattern:    regexp.MustCompile(`\b\d[\d,]*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|CAD|AUD)\b`),
			PatternRaw: `\b\d[\d,]*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|CAD|AUD)\b`,
			Confidence: 0.90,
		},
		{
			Type:       "PERCENTAGE",
			Pattern:    regexp.MustCompile(`\b\d+(?:\.\d+)?%`),
			PatternRaw: `\b\d+(?:\.\d+)?%`,
			Confidence: 0.90,
		},
		{
			Type:       "PHONE",
			Pattern:    regexp.MustCompile(`(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`),
			PatternRaw: `(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`,
			Confidence: 0.80,
		},
		{
			Type:       "SSN",
			Pattern:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			PatternRaw: `\b\d{3}-\d{2}-\d{4}\b`,
			Confidence: 0.80,
		},
		{
			Type:       "CREDIT_CARD",
			Pattern:    regexp.MustCompile(`\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b`),
			PatternRaw: `\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b`,
			Confidence: 0.70,
		},
		{
			Type:       "FILE_PATH",
			Pattern:    regexp.MustCompile(`(?:/[\w.\-]+)+|(?:[A-Za-z]:\\(?:[\w.\- ]+\\?)+)|(?:[\w.\-]+/)+[\w.\-]+`),
			PatternRaw: `(?:/[\w.\-]+)+|(?:[A-Za-z]:\\(?:[\w.\- ]+\\?)+)|(?:[\w.\-]+/)+[\w.\-]+`,
			Confidence: 0.75,
		},
		{
			Type:       "HASH",
			Pattern:    regexp.MustCompile(`\b(?:sha256:)?[a-fA-F0-9]{32,64}\b`),
			PatternRaw: `\b(?:sha256:)?[a-fA-F0-9]{32,64}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "TICKET_ID",
			Pattern:    regexp.MustCompile(`\b[A-Z][A-Z0-9]{1,9}-\d{1,8}\b`),
			PatternRaw: `\b[A-Z][A-Z0-9]{1,9}-\d{1,8}\b`,
			Confidence: 0.90,
		},
		{
			Type:       "CASE_ID",
			Pattern:    regexp.MustCompile(`\b(?:CASE|Case|case)[-_ ]?\d{3,12}\b`),
			PatternRaw: `\b(?:CASE|Case|case)[-_ ]?\d{3,12}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "INVOICE_ID",
			Pattern:    regexp.MustCompile(`\b(?:INV|Invoice|invoice)[-_ ]?[A-Z0-9]{3,16}\b`),
			PatternRaw: `\b(?:INV|Invoice|invoice)[-_ ]?[A-Z0-9]{3,16}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "CONTRACT_ID",
			Pattern:    regexp.MustCompile(`\b(?:CONTRACT|Contract|contract|CTR)[-_ ]?[A-Z0-9]{3,20}\b`),
			PatternRaw: `\b(?:CONTRACT|Contract|contract|CTR)[-_ ]?[A-Z0-9]{3,20}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "POLICY_ID",
			Pattern:    regexp.MustCompile(`\b(?:POLICY|Policy|policy|POL)[-_ ]?[A-Z0-9]{3,20}\b`),
			PatternRaw: `\b(?:POLICY|Policy|policy|POL)[-_ ]?[A-Z0-9]{3,20}\b`,
			Confidence: 0.85,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "ACCOUNT_ID",
			Pattern:    regexp.MustCompile(`\b(?:acct|account|ACC)[-_ ]?[A-Z0-9]{4,20}\b`),
			PatternRaw: `\b(?:acct|account|ACC)[-_ ]?[A-Z0-9]{4,20}\b`,
			Confidence: 0.80,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "API_KEY_PATTERN",
			Pattern:    regexp.MustCompile(`\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_\-]{12,}\b`),
			PatternRaw: `\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_\-]{12,}\b`,
			Confidence: 0.70,
		},
		{
			Type:       "TAX_ID",
			Pattern:    regexp.MustCompile(`\b(?:VAT|PAN|TIN|TAX)[-_ ]?[A-Z0-9]{5,20}\b`),
			PatternRaw: `\b(?:VAT|PAN|TIN|TAX)[-_ ]?[A-Z0-9]{5,20}\b`,
			Confidence: 0.80,
			Normalize:  strings.ToUpper,
		},
		{
			Type:       "ORG",
			Pattern:    regexp.MustCompile(`\b(?:[A-Z][a-zA-Z&]+(?:\s+[A-Z][a-zA-Z&]+)*)\s+(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?|Group|Holdings|Partners|Associates|Foundation|Institute|University|Technologies|Solutions|Systems|Services|International|Consulting|Enterprises)\b`),
			PatternRaw: `\b(?:[A-Z][a-zA-Z&]+(?:\s+[A-Z][a-zA-Z&]+)*)\s+(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?|Group|Holdings|Partners|Associates|Foundation|Institute|University|Technologies|Solutions|Systems|Services|International|Consulting|Enterprises)\b`,
			Confidence: 0.65,
		},
		{
			Type:       "PERSON",
			Pattern:    regexp.MustCompile(`\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b`),
			PatternRaw: `\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b`,
			Confidence: 0.60,
		},
	}
}

// AddRule adds a custom NER rule.
func (n *RuleBasedNER) AddRule(entityType, pattern string, confidence float64) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rules = append(n.rules, nerRule{
		Type:       entityType,
		Pattern:    re,
		PatternRaw: pattern,
		Confidence: confidence,
	})
	return nil
}

// ListRules returns the configured rule set without exposing compiled regexes.
func (n *RuleBasedNER) ListRules() []KGCustomNERRule {
	n.mu.RLock()
	defer n.mu.RUnlock()
	rules := make([]KGCustomNERRule, 0, len(n.rules))
	for _, rule := range n.rules {
		rules = append(rules, KGCustomNERRule{
			Type:       rule.Type,
			Pattern:    rule.PatternRaw,
			Confidence: rule.Confidence,
		})
	}
	return rules
}

// Extract finds all entities in the text using rule-based patterns.
func (n *RuleBasedNER) Extract(text string) []KGEntity {
	n.mu.RLock()
	rules := n.rules
	n.mu.RUnlock()

	seen := make(map[string]struct{})
	var entities []KGEntity

	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			surface := text[loc[0]:loc[1]]
			canonical := surface
			if rule.Normalize != nil {
				canonical = rule.Normalize(surface)
			}

			key := canonical + "|" + rule.Type
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			entities = append(entities, KGEntity{
				Surface:      surface,
				Canonical:    canonical,
				Type:         rule.Type,
				Confidence:   rule.Confidence,
				CanonicalKey: canonicalEntityKey(rule.Type, canonical),
				Identifiers:  map[string]string{strings.ToLower(rule.Type): canonical},
				StartByte:    loc[0],
				EndByte:      loc[1],
			})
		}
	}

	return entities
}

func canonicalEntityKey(entityType, canonical string) string {
	entityType = strings.TrimSpace(strings.ToLower(entityType))
	canonical = strings.TrimSpace(strings.ToLower(canonical))
	if entityType == "" || canonical == "" {
		return ""
	}
	return entityType + ":" + canonical
}

package velocity

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
			Confidence: 0.95,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "URL",
			Pattern:    regexp.MustCompile(`https?://[^\s<>"'` + "`" + `\)]+`),
			Confidence: 0.95,
			Normalize:  strings.ToLower,
		},
		{
			Type:       "IP_ADDRESS",
			Pattern:    regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			Confidence: 0.85,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`),
			Confidence: 0.95,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b\d{1,2}/\d{1,2}/\d{2,4}\b`),
			Confidence: 0.80,
		},
		{
			Type:       "DATE",
			Pattern:    regexp.MustCompile(`\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`),
			Confidence: 0.90,
		},
		{
			Type:       "MONEY",
			Pattern:    regexp.MustCompile(`\$[\d,]+(?:\.\d{2})?`),
			Confidence: 0.90,
		},
		{
			Type:       "MONEY",
			Pattern:    regexp.MustCompile(`\b\d[\d,]*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|CAD|AUD)\b`),
			Confidence: 0.90,
		},
		{
			Type:       "PERCENTAGE",
			Pattern:    regexp.MustCompile(`\b\d+(?:\.\d+)?%`),
			Confidence: 0.90,
		},
		{
			Type:       "PHONE",
			Pattern:    regexp.MustCompile(`(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`),
			Confidence: 0.80,
		},
		{
			Type:       "SSN",
			Pattern:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Confidence: 0.80,
		},
		{
			Type:       "CREDIT_CARD",
			Pattern:    regexp.MustCompile(`\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b`),
			Confidence: 0.70,
		},
		{
			Type:       "ORG",
			Pattern:    regexp.MustCompile(`\b(?:[A-Z][a-zA-Z&]+(?:\s+[A-Z][a-zA-Z&]+)*)\s+(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?|Group|Holdings|Partners|Associates|Foundation|Institute|University|Technologies|Solutions|Systems|Services|International|Consulting|Enterprises)\b`),
			Confidence: 0.65,
		},
		{
			Type:       "PERSON",
			Pattern:    regexp.MustCompile(`\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b`),
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
		Confidence: confidence,
	})
	return nil
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
				Surface:    surface,
				Canonical:  canonical,
				Type:       rule.Type,
				Confidence: rule.Confidence,
				StartByte:  loc[0],
				EndByte:    loc[1],
			})
		}
	}

	return entities
}

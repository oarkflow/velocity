package search

import (
	"regexp"
	"strings"
)

// nerRule is one regex-based entity-detection rule, ported faithfully
// from v1's pkg/kg/ner.go (RuleBasedNER) — the real technique v1 uses is
// pattern/regex matching, not a machine-learning NER model.
type nerRule struct {
	Type      string
	Pattern   *regexp.Regexp
	Normalize func(string) string
}

// defaultNERRules is the same rule set as v1's RuleBasedNER.initDefaultRules,
// covering EMAIL, URL, DOMAIN, IP_ADDRESS, DATE (three formats), MONEY (two
// formats), PERCENTAGE, PHONE, SSN, CREDIT_CARD, FILE_PATH, HASH, and
// several business-identifier patterns (TICKET_ID, CASE_ID, INVOICE_ID,
// CONTRACT_ID, POLICY_ID, ACCOUNT_ID, API_KEY_PATTERN, TAX_ID), plus
// simple ORG (company-suffix) and PERSON (honorific-prefixed name) rules.
func defaultNERRules() []nerRule {
	return []nerRule{
		{Type: "EMAIL", Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), Normalize: strings.ToLower},
		{Type: "URL", Pattern: regexp.MustCompile(`https?://[^\s<>"'` + "`" + `\)]+`), Normalize: strings.ToLower},
		{Type: "DOMAIN", Pattern: regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`), Normalize: strings.ToLower},
		{Type: "IP_ADDRESS", Pattern: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
		{Type: "DATE", Pattern: regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)},
		{Type: "DATE", Pattern: regexp.MustCompile(`\b\d{1,2}/\d{1,2}/\d{2,4}\b`)},
		{Type: "DATE", Pattern: regexp.MustCompile(`\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`)},
		{Type: "MONEY", Pattern: regexp.MustCompile(`\$[\d,]+(?:\.\d{2})?`)},
		{Type: "MONEY", Pattern: regexp.MustCompile(`\b\d[\d,]*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|CAD|AUD)\b`)},
		{Type: "PERCENTAGE", Pattern: regexp.MustCompile(`\b\d+(?:\.\d+)?%`)},
		{Type: "PHONE", Pattern: regexp.MustCompile(`(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`)},
		{Type: "SSN", Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{Type: "CREDIT_CARD", Pattern: regexp.MustCompile(`\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b`)},
		{Type: "FILE_PATH", Pattern: regexp.MustCompile(`(?:/[\w.\-]+)+|(?:[A-Za-z]:\\(?:[\w.\- ]+\\?)+)|(?:[\w.\-]+/)+[\w.\-]+`)},
		{Type: "HASH", Pattern: regexp.MustCompile(`\b(?:sha256:)?[a-fA-F0-9]{32,64}\b`), Normalize: strings.ToLower},
		{Type: "TICKET_ID", Pattern: regexp.MustCompile(`\b[A-Z][A-Z0-9]{1,9}-\d{1,8}\b`)},
		{Type: "CASE_ID", Pattern: regexp.MustCompile(`\b(?:CASE|Case|case)[-_ ]?\d{3,12}\b`), Normalize: strings.ToUpper},
		{Type: "INVOICE_ID", Pattern: regexp.MustCompile(`\b(?:INV|Invoice|invoice)[-_ ]?[A-Z0-9]{3,16}\b`), Normalize: strings.ToUpper},
		{Type: "CONTRACT_ID", Pattern: regexp.MustCompile(`\b(?:CONTRACT|Contract|contract|CTR)[-_ ]?[A-Z0-9]{3,20}\b`), Normalize: strings.ToUpper},
		{Type: "POLICY_ID", Pattern: regexp.MustCompile(`\b(?:POLICY|Policy|policy|POL)[-_ ]?[A-Z0-9]{3,20}\b`), Normalize: strings.ToUpper},
		{Type: "ACCOUNT_ID", Pattern: regexp.MustCompile(`\b(?:acct|account|ACC)[-_ ]?[A-Z0-9]{4,20}\b`), Normalize: strings.ToUpper},
		{Type: "API_KEY_PATTERN", Pattern: regexp.MustCompile(`\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_\-]{12,}\b`)},
		{Type: "TAX_ID", Pattern: regexp.MustCompile(`\b(?:VAT|PAN|TIN|TAX)[-_ ]?[A-Z0-9]{5,20}\b`), Normalize: strings.ToUpper},
		{Type: "ORG", Pattern: regexp.MustCompile(`\b(?:[A-Z][a-zA-Z&]+(?:\s+[A-Z][a-zA-Z&]+)*)\s+(?:Inc\.?|Corp\.?|LLC|Ltd\.?|Co\.?|Group|Holdings|Partners|Associates|Foundation|Institute|University|Technologies|Solutions|Systems|Services|International|Consulting|Enterprises)\b`)},
		{Type: "PERSON", Pattern: regexp.MustCompile(`\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b`)},
	}
}

// extractEntities runs every rule against text and returns non-duplicate
// matches (deduped by normalized-surface+type, same as v1), each carrying
// its byte-offset span.
func extractEntities(text string) []extractedEntity {
	rules := defaultNERRules()
	seen := make(map[string]struct{})
	var out []extractedEntity

	for _, rule := range rules {
		for _, loc := range rule.Pattern.FindAllStringIndex(text, -1) {
			surface := text[loc[0]:loc[1]]
			canonical := surface
			if rule.Normalize != nil {
				canonical = rule.Normalize(surface)
			}
			key := rule.Type + "|" + canonical
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, extractedEntity{
				Text:  surface,
				Type:  rule.Type,
				Start: loc[0],
				End:   loc[1],
			})
		}
	}
	return out
}

type extractedEntity struct {
	Text  string
	Type  string
	Start int
	End   int
}

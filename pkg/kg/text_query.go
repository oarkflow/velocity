package kg

import (
	"strings"
	"unicode"
)

type fullTextPlan struct {
	raw       string
	terms     []string
	phrases   []string
	prefixes  []string
	negative  []string
	anyMode   bool
	phraseAll bool
}

var kgStopWords = map[string]struct{}{
	// Domain-neutral English function words only. Terms that can carry meaning
	// in legal, healthcare, finance, support, evidence, or operations corpora
	// are intentionally preserved even if they are common in those domains.
	"a": {}, "about": {}, "above": {}, "after": {}, "again": {}, "against": {}, "all": {},
	"am": {}, "an": {}, "and": {}, "any": {}, "are": {}, "as": {}, "at": {}, "be": {},
	"because": {}, "been": {}, "before": {}, "being": {}, "below": {}, "between": {},
	"both": {}, "but": {}, "by": {}, "can": {}, "cannot": {}, "could": {}, "did": {},
	"do": {}, "does": {}, "doing": {}, "down": {}, "during": {}, "each": {}, "few": {},
	"for": {}, "from": {}, "further": {}, "had": {}, "has": {}, "have": {}, "having": {},
	"he": {}, "her": {}, "here": {}, "hers": {}, "herself": {}, "him": {}, "himself": {},
	"his": {}, "how": {}, "i": {}, "if": {}, "in": {}, "into": {}, "is": {}, "it": {},
	"its": {}, "itself": {}, "just": {}, "me": {}, "more": {}, "most": {}, "my": {},
	"myself": {}, "no": {}, "nor": {}, "not": {}, "now": {}, "of": {}, "off": {},
	"on": {}, "once": {}, "only": {}, "or": {}, "other": {}, "our": {}, "ours": {},
	"ourselves": {}, "out": {}, "over": {}, "own": {}, "same": {}, "she": {}, "should": {},
	"so": {}, "some": {}, "such": {}, "than": {}, "that": {}, "the": {}, "their": {},
	"theirs": {}, "them": {}, "themselves": {}, "then": {}, "there": {}, "these": {},
	"they": {}, "this": {}, "those": {}, "through": {}, "to": {}, "too": {}, "under": {},
	"until": {}, "up": {}, "very": {}, "was": {}, "we": {}, "were": {}, "what": {},
	"when": {}, "where": {}, "which": {}, "while": {}, "who": {}, "whom": {}, "why": {},
	"will": {}, "with": {}, "within": {}, "without": {}, "would": {}, "you": {}, "your": {},
	"yours": {}, "yourself": {}, "yourselves": {},
}

func parseFullTextQuery(text, matchMode string, prefixMatch bool) fullTextPlan {
	text = strings.TrimSpace(text)
	plan := fullTextPlan{raw: text}
	if text == "" {
		return plan
	}
	mode := strings.ToLower(strings.TrimSpace(matchMode))
	plan.anyMode = mode == "any"
	plan.phraseAll = mode == "phrase"
	if mode == "boolean" {
		plan.anyMode = strings.Contains(text, "|") || containsBooleanOR(text)
	}
	negateNext := false
	for _, token := range splitFullTextQuery(text) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		upper := strings.ToUpper(token)
		if upper == "OR" || token == "|" {
			plan.anyMode = true
			continue
		}
		if upper == "AND" {
			continue
		}
		if upper == "NOT" {
			negateNext = true
			continue
		}
		negative := negateNext
		negateNext = false
		if strings.HasPrefix(token, "-") && len(token) > 1 {
			negative = true
			token = strings.TrimPrefix(token, "-")
		}
		quoted := strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"") && len(token) >= 2
		if quoted {
			phrase := strings.TrimSpace(token[1 : len(token)-1])
			if phrase == "" {
				continue
			}
			if negative {
				plan.negative = append(plan.negative, tokenizeSearchStrict(strings.ToLower(phrase))...)
				continue
			}
			plan.phrases = append(plan.phrases, strings.ToLower(phrase))
			continue
		}
		prefix := strings.HasSuffix(token, "*") && len(token) > 1
		if prefix {
			token = strings.TrimSuffix(token, "*")
		}
		for _, term := range tokenizeSearchStrict(strings.ToLower(token)) {
			if negative {
				plan.negative = append(plan.negative, term)
			} else if prefix || prefixMatch {
				plan.prefixes = append(plan.prefixes, term)
			} else {
				plan.terms = append(plan.terms, term)
			}
		}
	}
	if plan.phraseAll && len(plan.phrases) == 0 {
		plan.phrases = []string{text}
		plan.terms = nil
	}
	plan.terms = dedupeStrings(plan.terms)
	plan.prefixes = dedupeStrings(plan.prefixes)
	plan.negative = dedupeStrings(plan.negative)
	return plan
}

func containsBooleanOR(text string) bool {
	for _, token := range splitFullTextQuery(text) {
		if strings.EqualFold(token, "OR") {
			return true
		}
	}
	return false
}

func splitFullTextQuery(text string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range text {
		switch {
		case r == '"':
			b.WriteRune(r)
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		case r == '|' && !inQuote:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			out = append(out, "|")
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func (p fullTextPlan) active() bool {
	return p.raw != ""
}

func (p fullTextPlan) indexTerms() []string {
	terms := make([]string, 0, len(p.terms)+len(p.phrases)*2)
	terms = append(terms, p.terms...)
	for _, phrase := range p.phrases {
		terms = append(terms, tokenizeSearchStrict(strings.ToLower(phrase))...)
	}
	return dedupeStrings(terms)
}

func tokenize(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func tokenizeSearch(s string) []string {
	return tokenizeSearchFiltered(s, true)
}

func tokenizeSearchStrict(s string) []string {
	return tokenizeSearchFiltered(s, false)
}

func tokenizeSearchFiltered(s string, fallbackAllStopWords bool) []string {
	s = strings.ToLower(s)
	tokens := tokenize(s)
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if isKGStopWord(token) {
			continue
		}
		out = append(out, token)
	}
	if len(out) == 0 && fallbackAllStopWords {
		return tokens
	}
	return out
}

func isKGStopWord(token string) bool {
	if tokenContainsDigit(token) || strings.Contains(token, "_") {
		return false
	}
	if isProtectedFuzzyTerm(token) {
		return false
	}
	_, ok := kgStopWords[token]
	return ok
}

func tokenContainsDigit(token string) bool {
	for _, r := range token {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsNormalizedPhrase(normalizedText, phrase string) bool {
	phraseTokens := tokenizeSearch(strings.ToLower(phrase))
	if len(phraseTokens) == 0 {
		return false
	}
	return strings.Contains(normalizedText, strings.Join(phraseTokens, " "))
}

func containsTokenPrefix(tokens []string, prefix string) bool {
	for _, token := range tokens {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

func termFrequency(tokens []string, term string) int {
	count := 0
	for _, token := range tokens {
		if token == term {
			count++
		}
	}
	return count
}

func prefixFrequency(tokens []string, prefix string) int {
	count := 0
	for _, token := range tokens {
		if strings.HasPrefix(token, prefix) {
			count++
		}
	}
	return count
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

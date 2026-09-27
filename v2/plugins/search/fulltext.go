package search

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/oarkflow/velocity/v2/api"
)

// fullTextIndex is a schema-less inverted-index full-text search
// implementation, ported in spirit from v1's search_index.go query
// parsing (parseFullTextQuery/splitFullTextQuery/tokenize): it supports
// plain terms (AND semantics — a doc must contain every term), quoted
// phrase matches, and negative terms via a leading "-" or the NOT
// keyword. It persists through api.KVService under the following key
// scheme:
//
//	search/ft/doc/<key>    -> JSON-encoded original fields map (for Remove and phrase matching)
//	search/ft/text/<key>   -> lowercased concatenation of all field values (for phrase substring matching)
//	search/ft/terms/<key>  -> JSON list of distinct terms indexed for this key (so Remove can clean up postings)
//	search/ft/idx/<term>/<key> -> decimal term frequency (the postings list for <term>, scanned by prefix)
type fullTextIndex struct {
	kv api.KVService
}

func newFullTextIndex(kv api.KVService) *fullTextIndex {
	return &fullTextIndex{kv: kv}
}

const (
	ftDocPfx   = "search/ft/doc/"
	ftTextPfx  = "search/ft/text/"
	ftTermsPfx = "search/ft/terms/"
	ftIdxPfx   = "search/ft/idx/"
)

func (f *fullTextIndex) Index(ctx context.Context, key string, fields map[string]any) error {
	if key == "" {
		return fmt.Errorf("search: index key must not be empty")
	}

	// Remove any prior indexing for this key first so re-indexing doesn't
	// leave stale postings behind.
	if err := f.Remove(ctx, key); err != nil {
		return err
	}

	var textParts []string
	for _, v := range fields {
		textParts = append(textParts, normalizeValue(v))
	}
	fullText := strings.Join(textParts, " ")
	lowerText := strings.ToLower(fullText)

	docData, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("search: encode fields for %q: %w", key, err)
	}
	if err := f.kv.Put(ctx, ftDocPfx+key, docData); err != nil {
		return err
	}
	if err := f.kv.Put(ctx, ftTextPfx+key, []byte(lowerText)); err != nil {
		return err
	}

	terms := tokenize(lowerText)
	freq := make(map[string]int, len(terms))
	for _, t := range terms {
		freq[t]++
	}

	termList := make([]string, 0, len(freq))
	for term, count := range freq {
		termList = append(termList, term)
		if err := f.kv.Put(ctx, ftIdxPfx+term+"/"+key, []byte(strconv.Itoa(count))); err != nil {
			return err
		}
	}
	termData, err := json.Marshal(termList)
	if err != nil {
		return err
	}
	return f.kv.Put(ctx, ftTermsPfx+key, termData)
}

func (f *fullTextIndex) Remove(ctx context.Context, key string) error {
	termData, found, err := f.kv.Get(ctx, ftTermsPfx+key)
	if err != nil {
		return err
	}
	if found {
		var terms []string
		if err := json.Unmarshal(termData, &terms); err == nil {
			for _, term := range terms {
				_ = f.kv.Delete(ctx, ftIdxPfx+term+"/"+key)
			}
		}
	}
	_ = f.kv.Delete(ctx, ftTermsPfx+key)
	_ = f.kv.Delete(ctx, ftDocPfx+key)
	_ = f.kv.Delete(ctx, ftTextPfx+key)
	return nil
}

func (f *fullTextIndex) Query(ctx context.Context, q string, limit int) ([]api.SearchHit, error) {
	plan := parseFullTextPlan(q)
	if len(plan.terms) == 0 && len(plan.phrases) == 0 {
		return nil, nil
	}

	// AND semantics: a candidate set per required term, intersected.
	var candidateSets []map[string]int // term -> per-key frequency
	for _, term := range plan.terms {
		postings, err := f.postingsForTerm(ctx, term)
		if err != nil {
			return nil, err
		}
		if len(postings) == 0 {
			return nil, nil // a required term has no matches at all
		}
		candidateSets = append(candidateSets, postings)
	}

	var keys map[string]float64 // key -> accumulated score
	if len(candidateSets) == 0 {
		keys = make(map[string]float64)
	} else {
		keys = make(map[string]float64, len(candidateSets[0]))
		for k, freq := range candidateSets[0] {
			keys[k] = float64(freq)
		}
		for _, set := range candidateSets[1:] {
			for k := range keys {
				freq, ok := set[k]
				if !ok {
					delete(keys, k)
					continue
				}
				keys[k] += float64(freq)
			}
		}
	}

	// Phrase filtering: require the lowercased concatenated text to
	// contain each phrase as a substring.
	for _, phrase := range plan.phrases {
		if len(keys) == 0 && len(candidateSets) > 0 {
			break
		}
		matched := make(map[string]float64)
		if len(candidateSets) == 0 && len(keys) == 0 {
			// No term candidates yet: seed from a phrase-only query by
			// scanning every indexed document's text. This is O(n) but
			// phrase-only queries are expected to be rare/small-scale.
			all, err := f.allDocKeys(ctx)
			if err != nil {
				return nil, err
			}
			for _, key := range all {
				keys[key] = 0
			}
		}
		for key := range keys {
			text, found, err := f.kv.Get(ctx, ftTextPfx+key)
			if err != nil {
				return nil, err
			}
			if found && strings.Contains(string(text), phrase) {
				matched[key] = keys[key] + 1
			}
		}
		keys = matched
	}

	// Negative-term exclusion.
	for _, neg := range plan.negative {
		if len(keys) == 0 {
			break
		}
		postings, err := f.postingsForTerm(ctx, neg)
		if err != nil {
			return nil, err
		}
		for k := range postings {
			delete(keys, k)
		}
	}

	hits := make([]api.SearchHit, 0, len(keys))
	for k, score := range keys {
		hits = append(hits, api.SearchHit{Key: k, Score: score})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Key < hits[j].Key
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, nil
}

// postingsForTerm returns key -> term frequency for every document
// containing term, by scanning the "search/ft/idx/<term>/" prefix.
func (f *fullTextIndex) postingsForTerm(ctx context.Context, term string) (map[string]int, error) {
	prefix := ftIdxPfx + term + "/"
	out := make(map[string]int)
	cursor := ""
	for {
		items, next, err := f.kv.Scan(ctx, prefix, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for fullKey, val := range items {
			key := strings.TrimPrefix(fullKey, prefix)
			count, _ := strconv.Atoi(string(val))
			out[key] = count
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

func (f *fullTextIndex) allDocKeys(ctx context.Context) ([]string, error) {
	var out []string
	cursor := ""
	for {
		items, next, err := f.kv.Scan(ctx, ftTextPfx, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for fullKey := range items {
			out = append(out, strings.TrimPrefix(fullKey, ftTextPfx))
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

// --- query parsing, ported in simplified form from v1's search_index.go ---

type fullTextPlan struct {
	terms    []string
	phrases  []string
	negative []string
}

func parseFullTextPlan(q string) fullTextPlan {
	text := strings.TrimSpace(q)
	var plan fullTextPlan
	if text == "" {
		return plan
	}

	tokens := splitFullTextQuery(text)
	negateNext := false
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		upper := strings.ToUpper(token)
		if upper == "AND" || upper == "OR" {
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
			phrase := strings.ToLower(strings.TrimSpace(token[1 : len(token)-1]))
			if phrase == "" {
				continue
			}
			if negative {
				plan.negative = append(plan.negative, tokenize(phrase)...)
				continue
			}
			plan.phrases = append(plan.phrases, phrase)
			continue
		}
		for _, term := range tokenize(strings.ToLower(token)) {
			if negative {
				plan.negative = append(plan.negative, term)
			} else {
				plan.terms = append(plan.terms, term)
			}
		}
	}
	plan.terms = dedupeStrings(plan.terms)
	plan.phrases = dedupeStrings(plan.phrases)
	plan.negative = dedupeStrings(plan.negative)
	return plan
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
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func tokenize(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func normalizeValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

var _ api.SearchIndex = (*fullTextIndex)(nil)

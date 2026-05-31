package kg

import "testing"

func TestTokenizeSearchRemovesStopWordsWithFallback(t *testing.T) {
	got := tokenizeSearch("the compliance and retrieval policy")
	want := []string{"compliance", "retrieval", "policy"}
	if len(got) != len(want) {
		t.Fatalf("tokens=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tokens=%v want=%v", got, want)
		}
	}
	allStop := tokenizeSearch("to be or not to be")
	if len(allStop) == 0 {
		t.Fatalf("all-stop-word query should fall back to original tokens")
	}
}

func TestTokenizeSearchDomainStopWordsPreserveImportantTerms(t *testing.T) {
	got := tokenizeSearch("the patient and invoice of CASE-12345 compliance report")
	want := []string{"patient", "invoice", "case", "12345", "compliance", "report"}
	if len(got) != len(want) {
		t.Fatalf("tokens=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tokens=%v want=%v", got, want)
		}
	}
	if isKGStopWord("case") || isKGStopWord("invoice") || isKGStopWord("patient") || isKGStopWord("hipaa") {
		t.Fatalf("domain-bearing tokens must not be stop words")
	}
	if isKGStopWord("review") || isKGStopWord("update") || isKGStopWord("subject") || isKGStopWord("document") {
		t.Fatalf("document/context tokens must remain searchable")
	}
	if isKGStopWord("case_12345") || isKGStopWord("2026") {
		t.Fatalf("identifier-like tokens must not be stop words")
	}
}

func TestLevenshteinDistanceAndFuzzyScore(t *testing.T) {
	prev := make([]int, 32)
	curr := make([]int, 32)
	if got := levenshteinDistance("retrieval", "retrival", 2, prev, curr); got != 1 {
		t.Fatalf("distance retrieval/retrival=%d want=1", got)
	}
	if got := levenshteinDistance("graph", "grahp", 2, prev, curr); got != 2 {
		t.Fatalf("distance graph/grahp=%d want=2", got)
	}
	score := fuzzyTokenScore([]string{"retrival", "grahp"}, []string{"retrieval", "graph"}, 2)
	if score <= 0.5 {
		t.Fatalf("expected useful fuzzy score for edit-distance matches, got %.4f", score)
	}
}

func TestProtectedTermsAreNotStopWords(t *testing.T) {
	got := tokenizeSearch("both left ears without fever")
	want := []string{"both", "left", "ears", "without", "fever"}
	if len(got) != len(want) {
		t.Fatalf("tokens=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tokens=%v want=%v", got, want)
		}
	}
}

func TestAccurateFuzzyRequiresProtectedTermsExactly(t *testing.T) {
	score := fuzzyTokenScore([]string{"both", "eers"}, []string{"both", "ears"}, 1)
	if score <= 0 {
		t.Fatalf("expected typo on non-protected token to match when protected term is exact")
	}
	score = fuzzyTokenScore([]string{"both", "eers"}, []string{"left", "ears"}, 1)
	if score != 0 {
		t.Fatalf("expected protected term mismatch to block fuzzy score, got %.4f", score)
	}
}

func TestAccurateFuzzyRequiresCodesExactly(t *testing.T) {
	score := fuzzyTokenScore([]string{"h60", "333", "diabetis"}, []string{"h60", "333", "diabetes"}, 1)
	if score <= 0 {
		t.Fatalf("expected typo to match when code terms are exact")
	}
	score = fuzzyTokenScore([]string{"h60", "333", "diabetis"}, []string{"h60", "332", "diabetes"}, 1)
	if score != 0 {
		t.Fatalf("expected code mismatch to block fuzzy score, got %.4f", score)
	}
}

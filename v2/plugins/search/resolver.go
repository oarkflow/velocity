package search

import (
	"sort"
	"strings"
)

// defaultResolveThreshold matches v1's EntityResolver default.
const defaultResolveThreshold = 0.85

// resolveClusters clusters ids whose strings are Jaro-Winkler similar
// above threshold, picks the most frequent string in each cluster as
// canonical (ties broken by lexical order, matching v1's pickCanonical),
// and returns one cluster per group. This is a faithful port of v1's
// pkg/kg/entity_resolver.go EntityResolver.Resolve/cluster/pickCanonical,
// adapted to operate on plain ID strings rather than KGEntity structs:
// api.GraphStore's AddEntity takes a caller-chosen ID string with no
// mandated "surface form" field, so the ID string itself is what gets
// compared — callers typically pass the entity's surface text (or a
// string derived from it) as the ID precisely so this comparison is
// meaningful.
func resolveClusters(ids []string, threshold float64) [][]string {
	if len(ids) <= 1 {
		return [][]string{ids}
	}
	if threshold <= 0 || threshold > 1 {
		threshold = defaultResolveThreshold
	}

	assigned := make([]bool, len(ids))
	var clusters [][]int
	for i := range ids {
		if assigned[i] {
			continue
		}
		cluster := []int{i}
		assigned[i] = true
		for j := range ids {
			if assigned[j] {
				continue
			}
			if jaroWinkler(strings.ToLower(ids[i]), strings.ToLower(ids[j])) >= threshold {
				cluster = append(cluster, j)
				assigned[j] = true
			}
		}
		clusters = append(clusters, cluster)
	}

	out := make([][]string, 0, len(clusters))
	for _, cluster := range clusters {
		group := make([]string, len(cluster))
		for k, idx := range cluster {
			group[k] = ids[idx]
		}
		out = append(out, group)
	}
	return out
}

// pickCanonical returns the most frequent string in group (ties broken
// lexically), matching v1's pickCanonical.
func pickCanonical(group []string) string {
	freq := make(map[string]int, len(group))
	for _, s := range group {
		freq[s]++
	}
	type sf struct {
		s string
		n int
	}
	sorted := make([]sf, 0, len(freq))
	for s, n := range freq {
		sorted = append(sorted, sf{s, n})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].n != sorted[j].n {
			return sorted[i].n > sorted[j].n
		}
		return sorted[i].s < sorted[j].s
	})
	return sorted[0].s
}

// jaroWinkler computes Jaro-Winkler similarity, ported verbatim from v1's
// pkg/kg/entity_resolver.go.
func jaroWinkler(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	j := jaroSimilarity(s1, s2)

	prefixLen := 0
	const maxPrefix = 4
	for i := 0; i < len(s1) && i < len(s2) && i < maxPrefix; i++ {
		if s1[i] != s2[i] {
			break
		}
		prefixLen++
	}

	return j + float64(prefixLen)*0.1*(1.0-j)
}

func jaroSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	r1 := []rune(s1)
	r2 := []rune(s2)
	l1, l2 := len(r1), len(r2)

	matchDist := 0
	if l1 > l2 {
		matchDist = l1/2 - 1
	} else {
		matchDist = l2/2 - 1
	}
	if matchDist < 0 {
		matchDist = 0
	}

	s1Matches := make([]bool, l1)
	s2Matches := make([]bool, l2)

	matches := 0
	transpositions := 0

	for i := 0; i < l1; i++ {
		start := i - matchDist
		if start < 0 {
			start = 0
		}
		end := i + matchDist + 1
		if end > l2 {
			end = l2
		}
		for j := start; j < end; j++ {
			if s2Matches[j] || r1[i] != r2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	k := 0
	for i := 0; i < l1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if r1[i] != r2[k] {
			transpositions++
		}
		k++
	}

	m := float64(matches)
	return (m/float64(l1) + m/float64(l2) + (m-float64(transpositions)/2.0)/m) / 3.0
}

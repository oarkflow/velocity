package velocity

import (
	"sort"
	"strings"
)

// EntityResolver deduplicates entities using Jaro-Winkler string similarity.
type EntityResolver struct {
	Threshold float64 // similarity threshold (default 0.85)
}

func NewEntityResolver(threshold float64) *EntityResolver {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.85
	}
	return &EntityResolver{Threshold: threshold}
}

// Resolve deduplicates entities by grouping similar surface forms within each type.
func (r *EntityResolver) Resolve(entities []KGEntity) []KGEntity {
	if len(entities) <= 1 {
		return entities
	}

	// Group by type
	byType := make(map[string][]int)
	for i, e := range entities {
		byType[e.Type] = append(byType[e.Type], i)
	}

	var resolved []KGEntity
	for _, indices := range byType {
		clusters := r.cluster(entities, indices)
		for _, cluster := range clusters {
			canonical := r.pickCanonical(entities, cluster)
			for _, idx := range cluster {
				e := entities[idx]
				e.Canonical = canonical
				resolved = append(resolved, e)
			}
		}
	}

	return resolved
}

func (r *EntityResolver) cluster(entities []KGEntity, indices []int) [][]int {
	assigned := make(map[int]bool)
	var clusters [][]int

	for _, i := range indices {
		if assigned[i] {
			continue
		}
		cluster := []int{i}
		assigned[i] = true

		for _, j := range indices {
			if assigned[j] {
				continue
			}
			sim := jaroWinkler(
				strings.ToLower(entities[i].Surface),
				strings.ToLower(entities[j].Surface),
			)
			if sim >= r.Threshold {
				cluster = append(cluster, j)
				assigned[j] = true
			}
		}
		clusters = append(clusters, cluster)
	}

	return clusters
}

func (r *EntityResolver) pickCanonical(entities []KGEntity, cluster []int) string {
	// Pick the most frequent surface form
	freq := make(map[string]int)
	for _, idx := range cluster {
		freq[entities[idx].Surface]++
	}
	type sf struct {
		surface string
		count   int
	}
	var sorted []sf
	for s, c := range freq {
		sorted = append(sorted, sf{s, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].surface < sorted[j].surface
	})
	return sorted[0].surface
}

// jaroWinkler computes Jaro-Winkler similarity between two strings.
func jaroWinkler(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	jaro := jaroSimilarity(s1, s2)

	// Winkler prefix bonus
	prefixLen := 0
	maxPrefix := 4
	for i := 0; i < len(s1) && i < len(s2) && i < maxPrefix; i++ {
		if s1[i] != s2[i] {
			break
		}
		prefixLen++
	}

	return jaro + float64(prefixLen)*0.1*(1.0-jaro)
}

func jaroSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	r1 := []rune(s1)
	r2 := []rune(s2)
	l1 := len(r1)
	l2 := len(r2)

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

package kg

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"
)

// KGReranker optionally reranks search results.
type KGReranker interface {
	Rerank(ctx context.Context, query string, hits []KGSearchHit) ([]KGSearchHit, error)
}

// KGSearchEngine performs hybrid BM25 + vector search with RRF fusion.
type KGSearchEngine struct {
	db          Store
	hnsw        *HNSWIndex
	embedder    KGEmbedder
	reranker    KGReranker
	em          EntityStore
	cacheMu     sync.RWMutex
	chunkCache  map[string]KGChunk
	docCache    map[string]KGDocument
	indexMu     sync.RWMutex
	initialized bool
	indexDirty  bool
	deferIndex  bool
	termIndex   map[string][]string
	fuzzyIndex  map[string][]string
	chunkText   map[string]string
	chunkTerms  map[string][]string
	chunkNorm   map[string]string
}

func NewKGSearchEngine(db Store, hnsw *HNSWIndex, embedder KGEmbedder, em EntityStore) *KGSearchEngine {
	indexDirty := false
	initialized := true
	if data, err := db.Get([]byte(kgStatsKey)); err == nil {
		var stats KGCorpusStats
		if json.Unmarshal(data, &stats) == nil && stats.Chunks > 0 {
			indexDirty = true
			initialized = false
		}
	}
	return &KGSearchEngine{
		db:          db,
		hnsw:        hnsw,
		embedder:    embedder,
		em:          em,
		chunkCache:  make(map[string]KGChunk),
		docCache:    make(map[string]KGDocument),
		initialized: initialized,
		indexDirty:  indexDirty,
		termIndex:   make(map[string][]string),
		fuzzyIndex:  make(map[string][]string),
		chunkText:   make(map[string]string),
		chunkTerms:  make(map[string][]string),
		chunkNorm:   make(map[string]string),
	}
}

// SetReranker sets an optional reranker.
func (s *KGSearchEngine) SetReranker(r KGReranker) {
	s.reranker = r
}

// Search executes a hybrid search query.
func (s *KGSearchEngine) Search(ctx context.Context, req *KGSearchRequest) (*KGSearchResponse, error) {
	start := time.Now()

	if req.Query == "" {
		return nil, fmt.Errorf("query is required")
	}

	// Defaults
	limit := req.Limit
	if limit <= 0 {
		limit = 10
	}
	bm25Weight := req.BM25Weight
	vecWeight := req.VectorWeight
	if bm25Weight <= 0 && vecWeight <= 0 {
		bm25Weight = 0.5
		vecWeight = 0.5
	}

	mode := req.Mode
	if mode == "" {
		if req.EnableVector && s.hnsw != nil && s.embedder != nil {
			mode = KGSearchModeHybrid
		} else {
			mode = KGSearchModeKeyword
		}
	}

	overFetch := limit * 3
	const rrfK = 60.0

	// Track candidates: chunkID -> scores
	type candidate struct {
		bm25Rank  int
		vecRank   int
		fuzzyRank int
		score     float64
		text      []byte
	}
	candidates := make(map[string]candidate, overFetch)

	// --- BM25 retrieval ---
	if mode == KGSearchModeKeyword || mode == KGSearchModeHybrid {
		bm25Results := s.bm25Search(req, overFetch)
		for rank, res := range bm25Results {
			chunkID := res.chunkID
			c := candidates[chunkID]
			if c.bm25Rank == 0 && c.vecRank == 0 && c.fuzzyRank == 0 {
				c = candidate{bm25Rank: -1, vecRank: -1, fuzzyRank: -1}
			}
			c.bm25Rank = rank + 1
			c.text = unsafeStringBytes(res.text)
			candidates[chunkID] = c
		}
	}

	if req.Fuzzy && (mode == KGSearchModeKeyword || mode == KGSearchModeHybrid) && len(candidates) < limit {
		fuzzyResults := s.fuzzySearch(req, overFetch)
		for rank, res := range fuzzyResults {
			chunkID := res.chunkID
			if chunkID == "" {
				continue
			}
			c := candidates[chunkID]
			if c.bm25Rank == 0 && c.vecRank == 0 && c.fuzzyRank == 0 {
				c = candidate{bm25Rank: -1, vecRank: -1, fuzzyRank: -1}
			}
			if c.fuzzyRank < 0 {
				c.fuzzyRank = rank + 1
			}
			if len(c.text) == 0 {
				c.text = res.text
			}
			candidates[chunkID] = c
		}
	}

	// --- Vector retrieval ---
	if (mode == KGSearchModeSemantic || mode == KGSearchModeHybrid) &&
		s.hnsw != nil && s.embedder != nil {
		queryVec, err := s.embedder.Embed(ctx, req.Query)
		if err == nil && len(queryVec) > 0 {
			vecResults, err := s.hnsw.Search(queryVec, overFetch)
			if err == nil {
				for rank, res := range vecResults {
					c := candidates[res.ChunkID]
					if c.bm25Rank == 0 && c.vecRank == 0 && c.fuzzyRank == 0 {
						c = candidate{bm25Rank: -1, vecRank: -1, fuzzyRank: -1}
					}
					c.vecRank = rank + 1
					candidates[res.ChunkID] = c
				}
			}
		}
	}

	// --- RRF Fusion ---
	for id, c := range candidates {
		if c.bm25Rank > 0 {
			c.score += bm25Weight * (1.0 / (rrfK + float64(c.bm25Rank)))
		}
		if c.vecRank > 0 {
			c.score += vecWeight * (1.0 / (rrfK + float64(c.vecRank)))
		}
		if c.fuzzyRank > 0 {
			c.score += bm25Weight * 0.45 * (1.0 / (rrfK + float64(c.fuzzyRank)))
		}
		candidates[id] = c
	}

	// Sort by fused score
	type scoredCandidate struct {
		chunkID string
		score   float64
		bm25    float64
		vec     float64
		text    []byte
	}
	sorted := make([]scoredCandidate, 0, len(candidates))
	for id, c := range candidates {
		bm25Score := 0.0
		vecScore := 0.0
		if c.bm25Rank > 0 {
			bm25Score = 1.0 / (rrfK + float64(c.bm25Rank))
		} else if c.fuzzyRank > 0 {
			bm25Score = 0.45 / (rrfK + float64(c.fuzzyRank))
		}
		if c.vecRank > 0 {
			vecScore = 1.0 / (rrfK + float64(c.vecRank))
		}
		sorted = append(sorted, scoredCandidate{
			chunkID: id,
			score:   c.score,
			bm25:    bm25Score,
			vec:     vecScore,
			text:    c.text,
		})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].score > sorted[j].score
	})

	// --- Graph expansion ---
	graphNodes := 0
	if req.EnableGraph && s.em != nil && req.GraphDepth > 0 {
		topN := 5
		if topN > len(sorted) {
			topN = len(sorted)
		}
		for _, sc := range sorted[:topN] {
			chunk, ok := s.chunkMeta(sc.chunkID)
			if !ok {
				continue
			}
			related, err := s.em.GetRelatedEntities(ctx, chunk.DocID, "", req.GraphDepth)
			if err != nil || len(related) == 0 {
				continue
			}
			graphNodes += len(related)
		}
	}

	// Filter by min score
	if req.MinScore > 0 {
		filtered := sorted[:0]
		for _, c := range sorted {
			if c.score >= req.MinScore {
				filtered = append(filtered, c)
			}
		}
		sorted = filtered
	}

	// --- Hydrate results ---
	hits := make([]KGSearchHit, 0, len(sorted))
	seenResources := make(map[string]struct{}, limit)
	hydrateLimit := limit * 20
	if hydrateLimit < 100 {
		hydrateLimit = 100
	}
	if hydrateLimit > len(sorted) {
		hydrateLimit = len(sorted)
	}
	for _, c := range sorted[:hydrateLimit] {
		hit := s.hydrateHit(c.chunkID, c.text, c.score, c.bm25, c.vec)
		if hit != nil {
			// Apply metadata filters
			if len(req.Filters) > 0 && !matchFilters(hit.Metadata, req.Filters) {
				continue
			}
			resourceID := firstNonEmpty(hit.Source, hit.DocID, hit.ChunkID)
			if _, ok := seenResources[resourceID]; ok {
				continue
			}
			seenResources[resourceID] = struct{}{}
			hits = append(hits, *hit)
			if len(hits) >= limit {
				break
			}
		}
	}

	// --- Rerank ---
	if s.reranker != nil && len(hits) > 0 {
		reranked, err := s.reranker.Rerank(ctx, req.Query, hits)
		if err == nil {
			hits = reranked
		}
	}

	return &KGSearchResponse{
		Hits:        hits,
		TotalHits:   len(hits),
		QueryTimeMs: time.Since(start).Milliseconds(),
		Mode:        mode,
		GraphNodes:  graphNodes,
	}, nil
}

type kgTextCandidate struct {
	chunkID string
	text    string
	score   float64
}

func (s *KGSearchEngine) bm25Search(req *KGSearchRequest, limit int) []kgTextCandidate {
	if err := s.ensureTextIndex(); err != nil {
		return nil
	}
	plan := parseFullTextQuery(req.Query, req.MatchMode, req.PrefixMatch)
	if !plan.active() {
		return nil
	}
	ids := s.candidateChunkIDs(plan)
	if len(ids) == 0 {
		return nil
	}
	if plan.anyMode {
		ids = limitCandidateIDs(ids, searchCandidateScanLimit(limit))
	}
	out := make([]kgTextCandidate, 0, min(limit, len(ids)))
	s.indexMu.RLock()
	for _, id := range ids {
		text := s.chunkText[id]
		if text == "" {
			continue
		}
		terms := s.chunkTerms[id]
		norm := s.chunkNorm[id]
		if !kgPlanMatchesTokens(plan, terms, norm) {
			continue
		}
		out = append(out, kgTextCandidate{
			chunkID: id,
			text:    text,
			score:   kgFullTextScoreTokens(plan, terms, norm),
		})
	}
	s.indexMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].score == out[j].score {
			return out[i].chunkID < out[j].chunkID
		}
		return out[i].score > out[j].score
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

type kgFuzzyCandidate struct {
	chunkID string
	score   float64
	text    []byte
}

var kgProtectedFuzzyTerms = map[string]struct{}{
	"no": {}, "not": {}, "none": {}, "never": {}, "without": {}, "except": {},
	"neither": {}, "nor": {}, "negative": {}, "denies": {},
	"with": {}, "both": {}, "all": {}, "any": {}, "each": {}, "either": {},
	"every": {},
	"left":  {}, "right": {}, "bilateral": {}, "unilateral": {},
	"upper": {}, "lower": {}, "inner": {}, "outer": {}, "middle": {},
	"anterior": {}, "posterior": {}, "medial": {}, "lateral": {},
	"proximal": {}, "distal": {}, "superior": {}, "inferior": {},
	"before": {}, "after": {}, "during": {}, "prior": {}, "post": {}, "pre": {},
	"acute": {}, "chronic": {}, "subacute": {}, "recurrent": {}, "persistent": {},
	"intermittent": {}, "progressive": {},
	"mild": {}, "moderate": {}, "severe": {}, "critical": {},
	"active": {}, "inactive": {}, "resolved": {}, "unresolved": {},
	"confirmed": {}, "suspected": {}, "probable": {}, "possible": {},
	"icd": {}, "icd10": {}, "cpt": {}, "hcpcs": {}, "snomed": {}, "loinc": {},
	"rxnorm": {}, "dx": {}, "sx": {}, "hx": {}, "tx": {}, "rx": {},
}

func (s *KGSearchEngine) fuzzySearch(req *KGSearchRequest, limit int) []kgFuzzyCandidate {
	if err := s.ensureTextIndex(); err != nil {
		return nil
	}
	queryTerms := tokenizeSearch(strings.ToLower(req.Query))
	if len(queryTerms) == 0 {
		return nil
	}
	if !shouldUseFuzzyForTerms(queryTerms) {
		return nil
	}
	maxEdits := req.FuzzyMaxEdits
	if maxEdits <= 0 {
		maxEdits = 1
	}
	s.indexMu.RLock()
	candidateIDs := s.accurateFuzzyCandidateIDsLocked(queryTerms)
	if len(candidateIDs) == 0 {
		s.indexMu.RUnlock()
		return nil
	}
	candidateIDs = limitCandidateIDs(candidateIDs, fuzzyCandidateScanLimit(limit))
	candidates := make([]kgFuzzyCandidate, 0, min(limit, len(candidateIDs)))
	for _, id := range candidateIDs {
		terms := s.chunkTerms[id]
		score := fuzzyTokenScore(queryTerms, terms, maxEdits)
		if score <= 0 {
			continue
		}
		text := s.chunkText[id]
		candidates = append(candidates, kgFuzzyCandidate{
			chunkID: id,
			score:   score,
			text:    unsafeStringBytes(text),
		})
	}
	s.indexMu.RUnlock()
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].chunkID < candidates[j].chunkID
		}
		return candidates[i].score > candidates[j].score
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func (s *KGSearchEngine) ensureTextIndex() error {
	s.indexMu.RLock()
	initialized := s.initialized
	dirty := s.indexDirty
	s.indexMu.RUnlock()
	if initialized && !dirty {
		return nil
	}

	keys, err := s.db.Keys(kgChunkPrefix + "*")
	if err != nil {
		return err
	}
	termIndex := make(map[string][]string, len(keys)*8)
	fuzzyIndex := make(map[string][]string, len(keys)*12)
	chunkText := make(map[string]string, len(keys))
	chunkTerms := make(map[string][]string, len(keys))
	chunkNorm := make(map[string]string, len(keys))
	for _, key := range keys {
		data, err := s.db.Get([]byte(key))
		if err != nil {
			continue
		}
		chunkID := strings.TrimPrefix(key, kgChunkPrefix)
		text := string(data)
		chunkText[chunkID] = text
		terms := tokenizeSearch(strings.ToLower(text))
		chunkTerms[chunkID] = terms
		chunkNorm[chunkID] = strings.Join(terms, " ")
		seen := make(map[string]struct{}, 16)
		for _, term := range terms {
			if _, ok := seen[term]; ok {
				continue
			}
			seen[term] = struct{}{}
			termIndex[term] = append(termIndex[term], chunkID)
			for _, gram := range fuzzyCandidateGrams(term) {
				fuzzyIndex[gram] = append(fuzzyIndex[gram], chunkID)
			}
		}
	}
	for term, ids := range termIndex {
		sort.Strings(ids)
		termIndex[term] = ids
	}
	for gram, ids := range fuzzyIndex {
		sort.Strings(ids)
		fuzzyIndex[gram] = uniqueSortedStrings(ids)
	}

	s.indexMu.Lock()
	s.termIndex = termIndex
	s.fuzzyIndex = fuzzyIndex
	s.chunkText = chunkText
	s.chunkTerms = chunkTerms
	s.chunkNorm = chunkNorm
	s.initialized = true
	s.indexDirty = false
	s.indexMu.Unlock()
	return nil
}

func (s *KGSearchEngine) indexDocument(docID string) error {
	if s == nil || docID == "" {
		return nil
	}
	s.indexMu.RLock()
	deferIndex := s.deferIndex
	canIncremental := s.initialized && !s.indexDirty && !deferIndex
	s.indexMu.RUnlock()
	if !canIncremental {
		s.markIndexDirty()
		return nil
	}
	doc, ok := s.docMeta(docID)
	if !ok {
		return nil
	}
	updates := make([]KGChunk, 0, doc.ChunkCount)
	for i := 0; i < doc.ChunkCount; i++ {
		chunkIDData, err := s.db.Get([]byte(fmt.Sprintf("%s%s:%d", kgChunkDocPrefix, docID, i)))
		if err != nil {
			continue
		}
		chunkID := string(chunkIDData)
		chunk, ok := s.chunkMeta(chunkID)
		if !ok {
			rawText, err := s.db.Get([]byte(kgChunkPrefix + chunkID))
			if err != nil {
				continue
			}
			chunk = KGChunk{ID: chunkID, DocID: docID, Index: i, Text: string(rawText)}
		}
		if chunk.Text == "" {
			rawText, err := s.db.Get([]byte(kgChunkPrefix + chunkID))
			if err != nil {
				continue
			}
			chunk.Text = string(rawText)
		}
		updates = append(updates, chunk)
	}
	if len(updates) == 0 {
		return nil
	}
	s.indexMu.Lock()
	for _, chunk := range updates {
		s.removeChunkFromTextIndexLocked(chunk.ID)
		terms := tokenizeSearch(strings.ToLower(chunk.Text))
		s.chunkText[chunk.ID] = chunk.Text
		s.chunkTerms[chunk.ID] = terms
		s.chunkNorm[chunk.ID] = strings.Join(terms, " ")
		seen := make(map[string]struct{}, len(terms))
		for _, term := range terms {
			if _, ok := seen[term]; ok {
				continue
			}
			seen[term] = struct{}{}
			s.termIndex[term] = append(s.termIndex[term], chunk.ID)
			for _, gram := range fuzzyCandidateGrams(term) {
				s.fuzzyIndex[gram] = append(s.fuzzyIndex[gram], chunk.ID)
			}
		}
	}
	s.initialized = true
	s.indexDirty = false
	s.indexMu.Unlock()
	return nil
}

func (s *KGSearchEngine) removeChunkFromTextIndexLocked(chunkID string) {
	if chunkID == "" {
		return
	}
	for _, term := range s.chunkTerms[chunkID] {
		s.termIndex[term] = removeTextIndexString(s.termIndex[term], chunkID)
		if len(s.termIndex[term]) == 0 {
			delete(s.termIndex, term)
		}
		for _, gram := range fuzzyCandidateGrams(term) {
			s.fuzzyIndex[gram] = removeTextIndexString(s.fuzzyIndex[gram], chunkID)
			if len(s.fuzzyIndex[gram]) == 0 {
				delete(s.fuzzyIndex, gram)
			}
		}
	}
	delete(s.chunkText, chunkID)
	delete(s.chunkTerms, chunkID)
	delete(s.chunkNorm, chunkID)
}

func (s *KGSearchEngine) candidateChunkIDs(plan fullTextPlan) []string {
	terms := plan.indexTerms()
	if len(terms) == 0 && len(plan.prefixes) == 0 {
		s.indexMu.RLock()
		ids := make([]string, 0, len(s.chunkText))
		for id := range s.chunkText {
			ids = append(ids, id)
		}
		s.indexMu.RUnlock()
		sort.Strings(ids)
		return ids
	}
	var candidates []string
	used := false
	s.indexMu.RLock()
	identifierTerms := make([]string, 0, len(terms))
	for _, term := range terms {
		if looksLikeIdentifierToken(term) {
			identifierTerms = append(identifierTerms, term)
		}
	}
	if len(identifierTerms) > 0 {
		for _, term := range identifierTerms {
			ids := sortedUniqueCopy(s.termIndex[term])
			if len(ids) == 0 {
				s.indexMu.RUnlock()
				return nil
			}
			if !used {
				candidates = append([]string(nil), ids...)
				used = true
			} else {
				candidates = intersectSortedStrings(candidates, ids)
			}
			if len(candidates) == 0 {
				s.indexMu.RUnlock()
				return nil
			}
		}
		s.indexMu.RUnlock()
		return candidates
	}
	for _, term := range terms {
		ids := sortedUniqueCopy(s.termIndex[term])
		if len(ids) == 0 {
			if !plan.anyMode {
				s.indexMu.RUnlock()
				return nil
			}
			continue
		}
		if !used {
			candidates = append([]string(nil), ids...)
			used = true
		} else if plan.anyMode {
			candidates = mergeSortedUniqueStrings(candidates, ids)
		} else {
			candidates = intersectSortedStrings(candidates, ids)
		}
		if !plan.anyMode && len(candidates) == 0 {
			s.indexMu.RUnlock()
			return nil
		}
	}
	for _, prefix := range plan.prefixes {
		var prefixIDs []string
		for term, ids := range s.termIndex {
			if strings.HasPrefix(term, prefix) {
				prefixIDs = mergeSortedUniqueStrings(prefixIDs, sortedUniqueCopy(ids))
			}
		}
		if len(prefixIDs) == 0 {
			if !plan.anyMode {
				s.indexMu.RUnlock()
				return nil
			}
			continue
		}
		if !used {
			candidates = prefixIDs
			used = true
		} else if plan.anyMode {
			candidates = mergeSortedUniqueStrings(candidates, prefixIDs)
		} else {
			candidates = intersectSortedStrings(candidates, prefixIDs)
		}
	}
	s.indexMu.RUnlock()
	return candidates
}

func mergeSortedUniqueStrings(a, b []string) []string {
	if len(a) == 0 {
		return append([]string(nil), b...)
	}
	if len(b) == 0 {
		return a
	}
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		default:
			out = append(out, b[j])
			j++
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	return out
}

func searchCandidateScanLimit(limit int) int {
	if limit <= 0 {
		limit = 10
	}
	n := limit * 5000
	if n < 25000 {
		return 25000
	}
	if n > 100000 {
		return 100000
	}
	return n
}

func fuzzyCandidateScanLimit(limit int) int {
	if limit <= 0 {
		limit = 10
	}
	n := limit * 1000
	if n < 5000 {
		return 5000
	}
	if n > 20000 {
		return 20000
	}
	return n
}

func limitCandidateIDs(ids []string, max int) []string {
	if max <= 0 || len(ids) <= max {
		return ids
	}
	out := make([]string, 0, max)
	step := float64(len(ids)) / float64(max)
	for i := 0; i < max; i++ {
		idx := int(float64(i) * step)
		if idx >= len(ids) {
			idx = len(ids) - 1
		}
		out = append(out, ids[idx])
	}
	return out
}

func intersectSortedStrings(a, b []string) []string {
	out := a[:0]
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

func unsafeStringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func fuzzyTokenScore(queryTerms []string, tokens []string, maxEdits int) float64 {
	if len(queryTerms) == 0 || len(tokens) == 0 {
		return 0
	}
	tokenSet := make(map[string]struct{}, len(tokens))
	maxTokenLen := 0
	for _, token := range tokens {
		t := normalizeFuzzyToken(token)
		if t == "" {
			continue
		}
		tokenSet[t] = struct{}{}
		if len(t) > maxTokenLen {
			maxTokenLen = len(t)
		}
	}
	if len(tokenSet) == 0 {
		return 0
	}
	prev := make([]int, maxTokenLen+1)
	curr := make([]int, maxTokenLen+1)
	score := 0.0
	required := 0
	matched := 0
	for _, rawQ := range queryTerms {
		q := normalizeFuzzyToken(rawQ)
		if q == "" {
			continue
		}
		required++
		if _, ok := tokenSet[q]; ok {
			score += 1
			matched++
			continue
		}
		if isProtectedFuzzyTerm(q) || isCodeOrIdentifierTerm(q) || !isSafeFuzzyToken(q) {
			continue
		}
		allowedEdits := maxAllowedFuzzyEdits(q)
		if maxEdits > 0 && maxEdits < allowedEdits {
			allowedEdits = maxEdits
		}
		if allowedEdits <= 0 {
			continue
		}
		best := 0.0
		for token := range tokenSet {
			if !isSafeFuzzyToken(token) {
				continue
			}
			if strings.HasPrefix(token, q) || strings.HasPrefix(q, token) {
				if best < 0.85 {
					best = 0.85
				}
				continue
			}
			distance := levenshteinDistance(q, token, allowedEdits, prev, curr)
			if distance > allowedEdits {
				continue
			}
			similarity := levenshteinSimilarity(q, token, distance)
			if similarity < minFuzzySimilarity(q) {
				continue
			}
			similarity *= 0.90
			if similarity > best {
				best = similarity
			}
		}
		if best > 0 {
			score += best
			matched++
		}
	}
	if required == 0 {
		return 0
	}
	if float64(matched)/float64(required) < 0.75 {
		return 0
	}
	return score / float64(required)
}

func kgPlanMatchesTokens(plan fullTextPlan, tokens []string, normalizedText string) bool {
	if !plan.active() {
		return true
	}
	if len(tokens) == 0 {
		return false
	}
	for _, term := range plan.negative {
		if containsKGToken(tokens, term) {
			return false
		}
	}
	positive := 0
	matched := 0
	for _, term := range plan.terms {
		positive++
		if containsKGToken(tokens, term) {
			matched++
		}
	}
	for _, phrase := range plan.phrases {
		positive++
		if containsNormalizedPhrase(normalizedText, phrase) {
			matched++
		}
	}
	for _, prefix := range plan.prefixes {
		positive++
		if containsTokenPrefix(tokens, prefix) {
			matched++
		}
	}
	if positive == 0 {
		return len(plan.negative) > 0
	}
	if plan.anyMode {
		return matched > 0
	}
	return matched == positive
}

func kgFullTextScoreTokens(plan fullTextPlan, tokens []string, normalizedText string) float64 {
	if !plan.active() || len(tokens) == 0 {
		return 0
	}
	score := 0.0
	for _, term := range plan.terms {
		score += float64(termFrequency(tokens, term))
	}
	for _, phrase := range plan.phrases {
		if containsNormalizedPhrase(normalizedText, phrase) {
			score += 4
		}
	}
	for _, prefix := range plan.prefixes {
		score += float64(prefixFrequency(tokens, prefix)) * 0.75
	}
	return score
}

func containsKGToken(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *KGSearchEngine) accurateFuzzyCandidateIDsLocked(queryTerms []string) []string {
	var candidates []string
	used := false
	for _, rawTerm := range queryTerms {
		term := normalizeFuzzyToken(rawTerm)
		if term == "" {
			continue
		}
		var termIDs []string
		if isProtectedFuzzyTerm(term) || isCodeOrIdentifierTerm(term) {
			termIDs = sortedUniqueCopy(s.termIndex[term])
			if len(termIDs) == 0 {
				return nil
			}
		} else if isSafeFuzzyToken(term) {
			for _, gram := range fuzzyCandidateGrams(term) {
				termIDs = mergeSortedUniqueStrings(termIDs, sortedUniqueCopy(s.fuzzyIndex[gram]))
			}
			if len(termIDs) == 0 {
				continue
			}
		} else {
			continue
		}
		if !used {
			candidates = append([]string(nil), termIDs...)
			used = true
		} else if isProtectedFuzzyTerm(term) || isCodeOrIdentifierTerm(term) {
			candidates = intersectSortedStrings(candidates, termIDs)
		} else {
			candidates = mergeSortedUniqueStrings(candidates, termIDs)
		}
		if used && len(candidates) == 0 {
			return nil
		}
	}
	return candidates
}

func normalizeFuzzyToken(token string) string {
	return strings.Trim(strings.TrimSpace(strings.ToLower(token)), ".,;:!?()[]{}\"'`")
}

func shouldUseFuzzyForTerms(queryTerms []string) bool {
	for _, term := range queryTerms {
		t := normalizeFuzzyToken(term)
		if t == "" || isProtectedFuzzyTerm(t) || isCodeOrIdentifierTerm(t) {
			continue
		}
		if isSafeFuzzyToken(t) {
			return true
		}
	}
	return false
}

func isSafeFuzzyToken(token string) bool {
	token = normalizeFuzzyToken(token)
	if len(token) < 4 {
		return false
	}
	hasLetter := false
	for _, r := range token {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			return false
		default:
			return false
		}
	}
	return hasLetter
}

func isProtectedFuzzyTerm(token string) bool {
	_, ok := kgProtectedFuzzyTerms[normalizeFuzzyToken(token)]
	return ok
}

func isCodeOrIdentifierTerm(token string) bool {
	token = normalizeFuzzyToken(token)
	if token == "" {
		return false
	}
	digits := 0
	letters := 0
	for _, r := range token {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			letters++
		case r == '-' || r == '_' || r == ':' || r == '/' || r == '.':
		default:
			return false
		}
	}
	if digits == 0 {
		return false
	}
	if letters > 0 {
		return true
	}
	return float64(digits)/float64(len(token)) >= 0.70
}

func maxAllowedFuzzyEdits(token string) int {
	switch n := len(normalizeFuzzyToken(token)); {
	case n <= 3:
		return 0
	case n <= 4:
		return 1
	default:
		return 2
	}
}

func minFuzzySimilarity(token string) float64 {
	if len(normalizeFuzzyToken(token)) <= 5 {
		return 0.60
	}
	return 0.84
}

func tokenNGrams(term string, n int) []string {
	if n <= 0 || len(term) < n {
		return nil
	}
	grams := make([]string, 0, len(term)-n+1)
	for i := 0; i <= len(term)-n; i++ {
		grams = append(grams, term[i:i+n])
	}
	return grams
}

func fuzzyCandidateGrams(term string) []string {
	term = normalizeFuzzyToken(term)
	if len(term) <= 5 {
		return tokenNGrams(term, 2)
	}
	return tokenNGrams(term, 3)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func sortedUniqueCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return uniqueSortedStrings(out)
}

func removeTextIndexString(values []string, value string) []string {
	if len(values) == 0 || value == "" {
		return values
	}
	out := values[:0]
	for _, current := range values {
		if current != value {
			out = append(out, current)
		}
	}
	return out
}

// levenshteinDistance returns the Levenshtein edit distance between two tokens,
// with an early-exit bound for fuzzy search.
func levenshteinDistance(a, b string, max int, prev, curr []int) int {
	if a == b {
		return 0
	}
	if max < 0 {
		max = 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	if d := len(a) - len(b); d > max || d < -max {
		if d < 0 {
			return -d
		}
		return d
	}
	if len(prev) < len(b)+1 || len(curr) < len(b)+1 {
		return max + 1
	}
	prev = prev[:len(b)+1]
	curr = curr[:len(b)+1]
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if curr[j] < rowMin {
				rowMin = curr[j]
			}
		}
		if rowMin > max {
			return rowMin
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func levenshteinSimilarity(a, b string, distance int) float64 {
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest == 0 {
		return 1
	}
	score := 1 - float64(distance)/float64(longest)
	if score < 0 {
		return 0
	}
	return score
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func (s *KGSearchEngine) hydrateHit(chunkID string, text []byte, score, bm25Score, vecScore float64) *KGSearchHit {
	chunk, ok := s.chunkMeta(chunkID)
	if !ok {
		if len(text) == 0 {
			rawText, err := s.db.Get([]byte(kgChunkPrefix + chunkID))
			if err != nil {
				return nil
			}
			text = rawText
		}
		chunk = KGChunk{ID: chunkID, Text: string(text)}
	} else if chunk.Text == "" && len(text) > 0 {
		chunk.Text = string(text)
	}

	hit := &KGSearchHit{
		ChunkID:   chunkID,
		DocID:     chunk.DocID,
		Text:      chunk.Text,
		Score:     score,
		BM25Score: bm25Score,
		VecScore:  vecScore,
		Entities:  chunk.Entities,
	}

	// Load parent document for metadata
	if doc, ok := s.docMeta(chunk.DocID); ok {
		hit.Source = doc.Source
		hit.Title = doc.Title
		hit.Metadata = doc.Metadata
	}

	return hit
}

func (s *KGSearchEngine) chunkMeta(chunkID string) (KGChunk, bool) {
	if chunkID == "" {
		return KGChunk{}, false
	}
	s.cacheMu.RLock()
	chunk, ok := s.chunkCache[chunkID]
	s.cacheMu.RUnlock()
	if ok {
		return chunk, true
	}
	data, err := s.db.Get([]byte(kgChunkMetaPrefix + chunkID))
	if err != nil {
		return KGChunk{}, false
	}
	if json.Unmarshal(data, &chunk) != nil {
		return KGChunk{}, false
	}
	s.cacheMu.Lock()
	s.chunkCache[chunkID] = chunk
	s.cacheMu.Unlock()
	return chunk, true
}

func (s *KGSearchEngine) docMeta(docID string) (KGDocument, bool) {
	if docID == "" {
		return KGDocument{}, false
	}
	s.cacheMu.RLock()
	doc, ok := s.docCache[docID]
	s.cacheMu.RUnlock()
	if ok {
		return doc, true
	}
	data, err := s.db.Get([]byte(kgDocPrefix + docID))
	if err != nil {
		return KGDocument{}, false
	}
	if json.Unmarshal(data, &doc) != nil {
		return KGDocument{}, false
	}
	s.cacheMu.Lock()
	s.docCache[docID] = doc
	s.cacheMu.Unlock()
	return doc, true
}

func (s *KGSearchEngine) invalidateDocument(docID string) {
	if s == nil || docID == "" {
		return
	}
	chunkIDs := make([]string, 0)
	for i := 0; ; i++ {
		chunkIDData, err := s.db.Get([]byte(fmt.Sprintf("%s%s:%d", kgChunkDocPrefix, docID, i)))
		if err != nil {
			break
		}
		chunkIDs = append(chunkIDs, string(chunkIDData))
	}
	s.indexMu.Lock()
	for _, chunkID := range chunkIDs {
		s.removeChunkFromTextIndexLocked(chunkID)
	}
	s.indexMu.Unlock()
	s.cacheMu.Lock()
	delete(s.docCache, docID)
	for chunkID, chunk := range s.chunkCache {
		if chunk.DocID == docID {
			delete(s.chunkCache, chunkID)
		}
	}
	s.cacheMu.Unlock()
}

func (s *KGSearchEngine) markIndexDirty() {
	if s == nil {
		return
	}
	s.indexMu.Lock()
	s.initialized = false
	s.indexDirty = true
	s.indexMu.Unlock()
}

func (s *KGSearchEngine) setDeferredIndexing(enabled bool) {
	if s == nil {
		return
	}
	s.indexMu.Lock()
	s.deferIndex = enabled
	if enabled {
		s.initialized = false
		s.indexDirty = true
	}
	s.indexMu.Unlock()
}

func (s *KGSearchEngine) deferredIndexing() bool {
	if s == nil {
		return false
	}
	s.indexMu.RLock()
	defer s.indexMu.RUnlock()
	return s.deferIndex
}

func matchFilters(metadata, filters map[string]string) bool {
	for k, v := range filters {
		if metadata == nil {
			return false
		}
		if metadata[k] != v {
			return false
		}
	}
	return true
}

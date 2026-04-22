package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KGReranker optionally reranks search results.
type KGReranker interface {
	Rerank(ctx context.Context, query string, hits []KGSearchHit) ([]KGSearchHit, error)
}

// KGSearchEngine performs hybrid BM25 + vector search with RRF fusion.
type KGSearchEngine struct {
	db       *DB
	hnsw     *HNSWIndex
	embedder KGEmbedder
	reranker KGReranker
	em       *EntityManager
}

func NewKGSearchEngine(db *DB, hnsw *HNSWIndex, embedder KGEmbedder, em *EntityManager) *KGSearchEngine {
	return &KGSearchEngine{
		db:       db,
		hnsw:     hnsw,
		embedder: embedder,
		em:       em,
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
		bm25Rank int
		vecRank  int
		score    float64
	}
	candidates := make(map[string]*candidate)

	// --- BM25 retrieval ---
	if mode == KGSearchModeKeyword || mode == KGSearchModeHybrid {
		bm25Results := s.bm25Search(req.Query, overFetch)
		for rank, res := range bm25Results {
			chunkID := extractChunkID(string(res.Key))
			if chunkID == "" {
				continue
			}
			c, ok := candidates[chunkID]
			if !ok {
				c = &candidate{bm25Rank: -1, vecRank: -1}
				candidates[chunkID] = c
			}
			c.bm25Rank = rank + 1
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
					c, ok := candidates[res.ChunkID]
					if !ok {
						c = &candidate{bm25Rank: -1, vecRank: -1}
						candidates[res.ChunkID] = c
					}
					c.vecRank = rank + 1
				}
			}
		}
	}

	// --- RRF Fusion ---
	for _, c := range candidates {
		if c.bm25Rank > 0 {
			c.score += bm25Weight * (1.0 / (rrfK + float64(c.bm25Rank)))
		}
		if c.vecRank > 0 {
			c.score += vecWeight * (1.0 / (rrfK + float64(c.vecRank)))
		}
	}

	// Sort by fused score
	type scoredCandidate struct {
		chunkID string
		score   float64
		bm25    float64
		vec     float64
	}
	var sorted []scoredCandidate
	for id, c := range candidates {
		bm25Score := 0.0
		vecScore := 0.0
		if c.bm25Rank > 0 {
			bm25Score = 1.0 / (rrfK + float64(c.bm25Rank))
		}
		if c.vecRank > 0 {
			vecScore = 1.0 / (rrfK + float64(c.vecRank))
		}
		sorted = append(sorted, scoredCandidate{
			chunkID: id,
			score:   c.score,
			bm25:    bm25Score,
			vec:     vecScore,
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
			chunkData, err := s.db.Get([]byte(kgChunkMetaPrefix + sc.chunkID))
			if err != nil {
				continue
			}
			var chunk KGChunk
			if json.Unmarshal(chunkData, &chunk) != nil {
				continue
			}
			related, err := s.em.GetRelatedEntities(ctx, chunk.DocID, "", req.GraphDepth)
			if err != nil || len(related) == 0 {
				continue
			}
			graphNodes += len(related)
		}
	}

	// Trim to limit
	if len(sorted) > limit {
		sorted = sorted[:limit]
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
	for _, c := range sorted {
		hit := s.hydrateHit(c.chunkID, c.score, c.bm25, c.vec)
		if hit != nil {
			// Apply metadata filters
			if len(req.Filters) > 0 && !matchFilters(hit.Metadata, req.Filters) {
				continue
			}
			hits = append(hits, *hit)
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

func (s *KGSearchEngine) bm25Search(query string, limit int) []SearchResult {
	results, err := s.db.Search(SearchQuery{
		Prefix:   kgChunkSearchPrefix,
		FullText: query,
		Limit:    limit,
	})
	if err != nil {
		return nil
	}
	return results
}

func (s *KGSearchEngine) hydrateHit(chunkID string, score, bm25Score, vecScore float64) *KGSearchHit {
	// Try chunk metadata first, fall back to raw chunk key
	var chunk KGChunk
	metaData, err := s.db.Get([]byte(kgChunkMetaPrefix + chunkID))
	if err == nil {
		if json.Unmarshal(metaData, &chunk) != nil {
			return nil
		}
	} else {
		// Fall back: raw text stored by PutIndexed
		rawText, err := s.db.Get([]byte(kgChunkPrefix + chunkID))
		if err != nil {
			return nil
		}
		chunk = KGChunk{ID: chunkID, Text: string(rawText)}
	}

	hit := &KGSearchHit{
		ChunkID:   chunkID,
		DocID:     chunk.DocID,
		Text:      chunk.Text,
		Score:     score,
		BM25Score: bm25Score,
		VecScore:  vecScore,
	}

	// Load parent document for metadata
	docData, err := s.db.Get([]byte(kgDocPrefix + chunk.DocID))
	if err == nil {
		var doc KGDocument
		if json.Unmarshal(docData, &doc) == nil {
			hit.Source = doc.Source
			hit.Title = doc.Title
			hit.Metadata = doc.Metadata
		}
	}

	return hit
}

func extractChunkID(key string) string {
	if strings.HasPrefix(key, kgChunkPrefix) {
		return key[len(kgChunkPrefix):]
	}
	return ""
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

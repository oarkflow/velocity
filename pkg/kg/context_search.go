package kg

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ContextSearch executes text search and expands the result set through
// persistent KG relations. Direct text hits keep their lexical/vector score;
// related resources receive a context score from the relation graph.
func (e *KnowledgeGraphEngine) ContextSearch(ctx context.Context, req *KGContextSearchRequest) (*KGContextSearchResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("context search request is required")
	}
	start := time.Now()
	limit := req.Limit
	if limit <= 0 {
		limit = 10
	}
	searchWeight := req.SearchWeight
	if searchWeight <= 0 {
		searchWeight = 1
	}
	contextWeight := req.ContextWeight
	if contextWeight <= 0 {
		contextWeight = 0.35
	}
	searchLimit := limit * 3
	if searchLimit < limit {
		searchLimit = limit
	}
	searchResp, err := e.Search(ctx, &KGSearchRequest{
		Query:         req.Query,
		Limit:         searchLimit,
		MinScore:      req.MinScore,
		Filters:       req.Filters,
		Mode:          req.Mode,
		MatchMode:     req.MatchMode,
		PrefixMatch:   req.PrefixMatch,
		Fuzzy:         req.Fuzzy,
		FuzzyMaxEdits: req.FuzzyMaxEdits,
		EnableVector:  req.EnableVector,
	})
	if err != nil {
		return nil, err
	}

	hits := make(map[string]*KGContextSearchHit, len(searchResp.Hits))
	seeds := make([]string, 0, len(searchResp.Hits))
	seenSeeds := map[string]struct{}{}
	for _, hit := range searchResp.Hits {
		resourceID := searchResourceID(hit)
		if resourceID == "" {
			continue
		}
		ctxHit := &KGContextSearchHit{
			KGSearchHit: hit,
			BaseScore:   hit.Score,
			FinalScore:  hit.Score * searchWeight,
			MatchKind:   "direct",
		}
		hits[resourceID] = ctxHit
		if _, ok := seenSeeds[resourceID]; !ok {
			seenSeeds[resourceID] = struct{}{}
			seeds = append(seeds, resourceID)
		}
	}

	var relations []KGRelation
	if len(seeds) > 0 {
		depth := req.GraphDepth
		if depth <= 0 {
			depth = 1
		}
		graph, err := e.QueryGraph(ctx, &KGGraphQuery{
			SeedIDs:       seeds,
			Depth:         depth,
			RelationTypes: req.RelationTypes,
			Direction:     req.Direction,
			MinConfidence: req.MinConfidence,
			Limit:         limit * 20,
		})
		if err != nil {
			return nil, err
		}
		relations = graph.Relations
		for _, rel := range relations {
			if !e.authorizedRelation(ctx, rel) {
				continue
			}
			score := relationContextScore(rel) * contextWeight
			for _, endpoint := range []string{rel.Source, rel.Target} {
				if endpoint == "" {
					continue
				}
				hit := hits[endpoint]
				if hit == nil {
					if !req.IncludeRelated {
						continue
					}
					related, ok := e.searchHitForSource(endpoint)
					if !ok {
						continue
					}
					hit = &KGContextSearchHit{
						KGSearchHit: related,
						MatchKind:   "related",
					}
					hits[endpoint] = hit
				}
				hit.ContextScore += score
				hit.FinalScore = hit.BaseScore*searchWeight + hit.ContextScore
				hit.RelatedRelations = append(hit.RelatedRelations, rel)
				if hit.MatchKind == "" {
					hit.MatchKind = "related"
				}
				if hit.BaseScore > 0 && hit.ContextScore > 0 {
					hit.MatchKind = "direct+context"
				}
			}
		}
	}

	out := make([]KGContextSearchHit, 0, len(hits))
	for _, hit := range hits {
		if hit.FinalScore == 0 {
			hit.FinalScore = hit.BaseScore*searchWeight + hit.ContextScore
		}
		hit.Score = hit.FinalScore
		out = append(out, *hit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FinalScore == out[j].FinalScore {
			return searchResourceID(out[i].KGSearchHit) < searchResourceID(out[j].KGSearchHit)
		}
		return out[i].FinalScore > out[j].FinalScore
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return &KGContextSearchResponse{
		Hits:        out,
		Relations:   relations,
		TotalHits:   len(out),
		QueryTimeMs: time.Since(start).Milliseconds(),
		Mode:        searchResp.Mode,
	}, nil
}

func relationContextScore(rel KGRelation) float64 {
	if rel.Confidence <= 0 {
		return 0.5
	}
	if rel.Confidence > 1 {
		return 1
	}
	return rel.Confidence
}

func searchResourceID(hit KGSearchHit) string {
	return firstNonEmpty(hit.Source, hit.DocID)
}

func (e *KnowledgeGraphEngine) searchHitForSource(source string) (KGSearchHit, bool) {
	source = strings.TrimSpace(source)
	if source == "" || e == nil || e.db == nil {
		return KGSearchHit{}, false
	}
	docIDData, err := e.db.Get([]byte(kgSourcePrefix + source))
	if err != nil {
		return KGSearchHit{}, false
	}
	docID := string(docIDData)
	doc, err := e.GetDocument(docID)
	if err != nil {
		return KGSearchHit{}, false
	}
	hit := KGSearchHit{
		DocID:    doc.ID,
		Source:   doc.Source,
		Title:    doc.Title,
		Metadata: doc.Metadata,
	}
	if doc.ChunkCount > 0 {
		chunkIDData, err := e.db.Get([]byte(fmt.Sprintf("%s%s:%d", kgChunkDocPrefix, doc.ID, 0)))
		if err == nil {
			chunkID := string(chunkIDData)
			if chunk, ok := e.search.chunkMeta(chunkID); ok {
				hit.ChunkID = chunk.ID
				hit.Text = chunk.Text
				if hit.Text == "" {
					if rawText, err := e.db.Get([]byte(kgChunkPrefix + chunk.ID)); err == nil {
						hit.Text = string(rawText)
					}
				}
				hit.Entities = chunk.Entities
			}
		}
	}
	return hit, true
}

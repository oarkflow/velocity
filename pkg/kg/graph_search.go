package kg

import (
	"context"
	"sort"
	"strconv"
)

func (e *KnowledgeGraphEngine) applyGraphSearchScoring(ctx context.Context, req *KGSearchRequest, resp *KGSearchResponse, limit int) error {
	if e == nil || e.graph == nil || resp == nil || req == nil || !req.EnableGraph || len(resp.Hits) == 0 {
		return nil
	}
	depth := req.GraphDepth
	if depth <= 0 {
		depth = 1
	}
	if depth > 8 {
		depth = 8
	}
	graphLimit := limit * 25
	if graphLimit < 100 {
		graphLimit = 100
	}

	type graphHit struct {
		hit          KGSearchHit
		baseScore    float64
		graphScore   float64
		bestDistance int
	}

	hits := make(map[string]*graphHit, len(resp.Hits)*2)
	seeds := make([]string, 0, len(resp.Hits))
	for _, hit := range resp.Hits {
		resourceID := searchResourceID(hit)
		if resourceID == "" {
			continue
		}
		current := hits[resourceID]
		if current == nil || hit.Score > current.baseScore {
			copyHit := hit
			hits[resourceID] = &graphHit{hit: copyHit, baseScore: hit.Score}
		}
		seeds = append(seeds, resourceID)
	}
	if len(seeds) == 0 {
		return nil
	}

	relations, distances, err := e.traverseScoredGraph(ctx, seeds, depth, graphLimit)
	if err != nil {
		return err
	}
	resp.GraphNodes = len(distances)
	for _, rel := range relations {
		if !e.authorizedRelation(ctx, rel) {
			continue
		}
		for _, endpoint := range []string{rel.Source, rel.Target} {
			distance, ok := distances[endpoint]
			if !ok {
				continue
			}
			score := relationContextScore(rel) / float64(distance+1)
			current := hits[endpoint]
			if current == nil {
				current = &graphHit{hit: KGSearchHit{Source: endpoint}}
				hits[endpoint] = current
			}
			if score > current.graphScore {
				current.graphScore = score
			}
			if current.bestDistance == 0 || distance < current.bestDistance {
				current.bestDistance = distance
			}
		}
	}

	scored := make([]struct {
		resourceID string
		hit        *graphHit
		score      float64
	}, 0, len(hits))
	for resourceID, gh := range hits {
		if gh == nil {
			continue
		}
		if gh.baseScore == 0 && gh.graphScore == 0 {
			continue
		}
		score := gh.baseScore + gh.graphScore
		scored = append(scored, struct {
			resourceID string
			hit        *graphHit
			score      float64
		}{resourceID: resourceID, hit: gh, score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].resourceID < scored[j].resourceID
		}
		return scored[i].score > scored[j].score
	})

	out := make([]KGSearchHit, 0, min(limit, len(scored)))
	for _, item := range scored {
		if len(out) >= limit {
			break
		}
		gh := item.hit
		if gh.hit.DocID == "" && gh.hit.ChunkID == "" {
			if related, ok := e.searchHitForSource(item.resourceID); ok {
				gh.hit = related
			} else {
				continue
			}
		}
		gh.hit.Score = item.score
		if gh.hit.Metadata == nil {
			gh.hit.Metadata = map[string]string{}
		}
		if gh.graphScore > 0 {
			gh.hit.Metadata["kg_graph_score"] = formatScore(gh.graphScore)
		}
		if gh.bestDistance > 0 {
			gh.hit.Metadata["kg_graph_distance"] = formatInt(gh.bestDistance)
		}
		if gh.hit.Source == "" {
			gh.hit.Source = item.resourceID
		}
		out = append(out, gh.hit)
	}
	resp.Hits = out
	resp.TotalHits = len(out)
	return nil
}

func (e *KnowledgeGraphEngine) traverseScoredGraph(ctx context.Context, seeds []string, depth, limit int) ([]KGRelation, map[string]int, error) {
	frontier := make(map[string]struct{}, len(seeds))
	distances := make(map[string]int, len(seeds))
	for _, seed := range seeds {
		if seed == "" {
			continue
		}
		frontier[seed] = struct{}{}
		distances[seed] = 0
	}
	relations := make([]KGRelation, 0, min(limit, 128))
	seenRelations := make(map[string]struct{}, limit)
	for d := 0; d < depth && len(frontier) > 0 && len(relations) < limit; d++ {
		next := map[string]struct{}{}
		for nodeID := range frontier {
			if len(relations) >= limit {
				break
			}
			remaining := limit - len(relations)
			perNodeLimit := remaining
			if perNodeLimit > 128 {
				perNodeLimit = 128
			}
			graphQuery := &KGGraphQuery{Depth: 1, Direction: KGRelationDirectionBoth, Limit: perNodeLimit}
			candidates, err := e.graph.relationsForNode(ctx, nodeID, graphQuery)
			if err != nil {
				return relations, distances, err
			}
			sort.Slice(candidates, func(i, j int) bool {
				if candidates[i].Confidence == candidates[j].Confidence {
					return candidates[i].RelationID < candidates[j].RelationID
				}
				return candidates[i].Confidence > candidates[j].Confidence
			})
			for _, rel := range candidates {
				if len(relations) >= limit {
					break
				}
				if rel.RelationID == "" {
					continue
				}
				if _, ok := seenRelations[rel.RelationID]; ok {
					continue
				}
				seenRelations[rel.RelationID] = struct{}{}
				relations = append(relations, rel)
				for _, endpoint := range []string{rel.Source, rel.Target} {
					if endpoint == "" || endpoint == nodeID {
						continue
					}
					if _, ok := distances[endpoint]; !ok {
						distances[endpoint] = d + 1
						next[endpoint] = struct{}{}
					}
				}
			}
		}
		frontier = next
	}
	return relations, distances, nil
}

func formatScore(score float64) string {
	return strconv.FormatFloat(score, 'f', 6, 64)
}

func formatInt(n int) string {
	return strconv.Itoa(n)
}

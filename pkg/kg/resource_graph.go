package kg

import (
	"context"
	"strings"
	"time"
)

// SearchResourceGraph searches KG-indexed resources and returns the inferred
// relationship graph between matching Velocity resources.
func (e *KnowledgeGraphEngine) SearchResourceGraph(ctx context.Context, req *KGResourceGraphRequest) (*KGResourceGraphResponse, error) {
	if req == nil {
		req = &KGResourceGraphRequest{}
	}
	start := time.Now()
	limit := req.Limit
	if limit <= 0 {
		limit = 10
	}
	searchResp, err := e.Search(ctx, &KGSearchRequest{
		Query:         req.Query,
		Limit:         limit,
		MinScore:      req.MinScore,
		Filters:       req.Filters,
		Mode:          req.Mode,
		MatchMode:     req.MatchMode,
		PrefixMatch:   req.PrefixMatch,
		Fuzzy:         req.Fuzzy,
		FuzzyMaxEdits: req.FuzzyMaxEdits,
		EnableGraph:   req.Depth > 0,
		GraphDepth:    req.Depth,
	})
	if err != nil {
		return nil, err
	}

	nodes := make([]KGResourceGraphNode, 0, len(searchResp.Hits))
	entityToNodes := make(map[string][]int)
	seenNode := make(map[string]int)

	for _, hit := range searchResp.Hits {
		source := hit.Source
		if source == "" {
			source = hit.DocID
		}
		if existing, ok := seenNode[source]; ok {
			nodes[existing].Score += hit.Score
			if nodes[existing].Snippet == "" {
				nodes[existing].Snippet = hit.Text
			}
			continue
		}

		entities := hit.Entities
		if len(entities) == 0 && e.ner != nil {
			entities = e.ner.Extract(hit.Title + "\n" + hit.Source + "\n" + hit.Text)
		}
		node := KGResourceGraphNode{
			ID:           source,
			Source:       source,
			ResourceType: ResourceType(hit.Metadata["resource_type"]),
			ResourceID:   resourceIDFromHit(hit),
			Title:        hit.Title,
			Snippet:      hit.Text,
			Score:        hit.Score,
			Metadata:     hit.Metadata,
			Entities:     entities,
		}
		if !req.IncludeRaw {
			node.Snippet = truncateKGSnippet(node.Snippet, 240)
		}
		seenNode[source] = len(nodes)
		nodes = append(nodes, node)
		for _, ent := range entities {
			key := kgEntityGraphKey(ent)
			if key == "" {
				continue
			}
			entityToNodes[key] = append(entityToNodes[key], len(nodes)-1)
		}
	}

	minShared := req.MinShared
	if minShared <= 0 {
		minShared = 1
	}
	edges := buildKGResourceGraphEdges(nodes, entityToNodes, minShared)

	return &KGResourceGraphResponse{
		Query:       req.Query,
		Nodes:       nodes,
		Edges:       edges,
		SearchHits:  searchResp.TotalHits,
		QueryTimeMs: time.Since(start).Milliseconds(),
		Mode:        searchResp.Mode,
	}, nil
}

func buildKGResourceGraphEdges(nodes []KGResourceGraphNode, entityToNodes map[string][]int, minShared int) []KGResourceGraphEdge {
	type pairKey struct {
		a string
		b string
	}
	type edgeAgg struct {
		source string
		target string
		entity KGEntity
		count  int
	}
	aggregated := make(map[pairKey]*edgeAgg)
	for entityKey, nodeIndexes := range entityToNodes {
		ent := entityForGraphKey(nodes[nodeIndexes[0]].Entities, entityKey)
		if ent.Canonical == "" {
			continue
		}
		for i := 0; i < len(nodeIndexes); i++ {
			for j := i + 1; j < len(nodeIndexes); j++ {
				a := nodes[nodeIndexes[i]]
				b := nodes[nodeIndexes[j]]
				if a.ID == b.ID {
					continue
				}
				key := pairKey{a: a.ID, b: b.ID}
				if key.a > key.b {
					key.a, key.b = key.b, key.a
				}
				agg := aggregated[key]
				if agg == nil {
					agg = &edgeAgg{source: key.a, target: key.b, entity: ent}
					aggregated[key] = agg
				}
				agg.count++
				if ent.Confidence > agg.entity.Confidence {
					agg.entity = ent
				}
			}
		}
	}

	edges := make([]KGResourceGraphEdge, 0, len(aggregated))
	for _, agg := range aggregated {
		if agg.count < minShared {
			continue
		}
		edges = append(edges, KGResourceGraphEdge{
			Source:       agg.source,
			Target:       agg.target,
			RelationType: "mentions_same_entity",
			Entity:       agg.entity,
			Weight:       float64(agg.count),
			Metadata: map[string]string{
				"shared_entities": intString(agg.count),
			},
		})
	}
	return edges
}

func entityForGraphKey(entities []KGEntity, want string) KGEntity {
	var best KGEntity
	for _, ent := range entities {
		if kgEntityGraphKey(ent) == want && ent.Confidence >= best.Confidence {
			best = ent
		}
	}
	return best
}

func kgEntityGraphKey(ent KGEntity) string {
	canonical := strings.TrimSpace(ent.Canonical)
	if canonical == "" {
		canonical = strings.TrimSpace(ent.Surface)
	}
	if canonical == "" || ent.Type == "" {
		return ""
	}
	return strings.ToLower(ent.Type) + ":" + strings.ToLower(canonical)
}

func resourceIDFromHit(hit KGSearchHit) string {
	if hit.Metadata != nil {
		for _, key := range []string{"key", "path", "name", "envelope_id", "entity_id", "row_key"} {
			if hit.Metadata[key] != "" {
				return hit.Metadata[key]
			}
		}
	}
	return hit.Source
}

func truncateKGSnippet(text string, max int) string {
	text = strings.TrimSpace(text)
	if max <= 0 || len(text) <= max {
		return text
	}
	return strings.TrimSpace(text[:max]) + "..."
}

func intString(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}

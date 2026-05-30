package kg

import (
	"context"
	"fmt"
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
		types  map[string]int
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
					agg = &edgeAgg{source: key.a, target: key.b, entity: ent, types: make(map[string]int)}
					aggregated[key] = agg
				}
				agg.count++
				agg.types[ent.Type]++
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
		relationType := inferResourceRelationType(nodesByID(nodes, agg.source), nodesByID(nodes, agg.target), agg.entity, agg.count)
		confidence := inferResourceRelationConfidence(agg.entity, agg.count)
		evidence := fmt.Sprintf("Both resources mention %s entity %q", agg.entity.Type, firstNonEmpty(agg.entity.Canonical, agg.entity.Surface))
		edges = append(edges, KGResourceGraphEdge{
			Source:       agg.source,
			Target:       agg.target,
			RelationType: relationType,
			Entity:       agg.entity,
			Weight:       float64(agg.count),
			Confidence:   confidence,
			Evidence:     evidence,
			SourceKind:   "inferred",
			CreatedBy:    "kg-resource-graph",
			CreatedAt:    time.Now().UTC(),
			Attributes: map[string]string{
				"entity_key": kgEntityGraphKey(agg.entity),
			},
			Metadata: map[string]string{
				"shared_entities": intString(agg.count),
				"evidence":        evidence,
				"source_kind":     "inferred",
			},
		})
	}
	return edges
}

func nodesByID(nodes []KGResourceGraphNode, id string) KGResourceGraphNode {
	for _, node := range nodes {
		if node.ID == id {
			return node
		}
	}
	return KGResourceGraphNode{ID: id}
}

func inferResourceRelationType(a, b KGResourceGraphNode, ent KGEntity, shared int) string {
	switch strings.ToUpper(ent.Type) {
	case "EMAIL", "DOMAIN", "URL", "ORG", "PERSON":
		if sameResourceFamily(a, b) {
			return "same_as"
		}
	case "TICKET_ID", "CASE_ID", "INVOICE_ID", "CONTRACT_ID", "POLICY_ID", "ACCOUNT_ID":
		return "references"
	}
	if shared > 1 {
		return "related_to"
	}
	return "mentions_same_entity"
}

func inferResourceRelationConfidence(ent KGEntity, shared int) float64 {
	confidence := ent.Confidence
	if confidence <= 0 {
		confidence = 0.5
	}
	confidence += float64(shared-1) * 0.05
	if confidence > 0.99 {
		return 0.99
	}
	return confidence
}

func sameResourceFamily(a, b KGResourceGraphNode) bool {
	return a.ResourceType != "" && a.ResourceType == b.ResourceType
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
	if ent.CanonicalKey != "" {
		return strings.ToLower(ent.CanonicalKey)
	}
	canonical := strings.TrimSpace(ent.Canonical)
	if canonical == "" {
		canonical = strings.TrimSpace(ent.Surface)
	}
	if canonical == "" || ent.Type == "" {
		return ""
	}
	return strings.ToLower(ent.Type) + ":" + strings.ToLower(canonical)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

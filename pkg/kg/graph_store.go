package kg

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KGGraphStore owns persistent KG relations, ontology state, and mutation logs.
type KGGraphStore struct {
	db Store
}

func NewKGGraphStore(db Store) *KGGraphStore {
	return &KGGraphStore{db: db}
}

func (s *KGGraphStore) CreateRelation(ctx context.Context, req *KGRelationRequest) (*KGRelation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("graph store unavailable")
	}
	if req == nil {
		return nil, fmt.Errorf("relation request is required")
	}
	source := strings.TrimSpace(req.Source)
	target := strings.TrimSpace(req.Target)
	relationType := strings.TrimSpace(req.RelationType)
	if source == "" || target == "" || relationType == "" {
		return nil, fmt.Errorf("source, target, and relation_type are required")
	}
	if resolved, _, err := s.ResolveEntity(ctx, source); err == nil {
		source = resolved
	}
	if resolved, _, err := s.ResolveEntity(ctx, target); err == nil {
		target = resolved
	}
	now := time.Now().UTC()
	rel := &KGRelation{
		RelationID:   firstNonEmpty(req.RelationID, stableRelationID(source, relationType, target, req.SourceKind)),
		Source:       source,
		Target:       target,
		RelationType: relationType,
		Direction:    normalizeRelationDirection(req.Direction),
		Confidence:   req.Confidence,
		Evidence:     strings.TrimSpace(req.Evidence),
		SourceKind:   strings.TrimSpace(req.SourceKind),
		SourceRefs:   req.SourceRefs,
		Status:       normalizeRelationStatus(req.Status),
		CreatedBy:    strings.TrimSpace(req.CreatedBy),
		CreatedAt:    now,
		UpdatedAt:    now,
		Revision:     1,
		Metadata:     cloneStringMap(req.Metadata),
		Attributes:   cloneStringMap(req.Attributes),
	}
	if rel.Confidence <= 0 {
		rel.Confidence = 1
	}
	if err := s.ValidateRelation(ctx, rel); err != nil {
		return nil, err
	}
	if existing, err := s.GetRelation(ctx, rel.RelationID); err == nil && existing.Status != KGRelationStatusDeleted {
		return nil, fmt.Errorf("relation already exists: %s", rel.RelationID)
	}
	if err := s.putRelation(rel); err != nil {
		return nil, err
	}
	return rel, s.appendMutation("create", "relation", rel.RelationID, rel.CreatedBy, rel.Revision)
}

func (s *KGGraphStore) GetRelation(ctx context.Context, relationID string) (*KGRelation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relationID = strings.TrimSpace(relationID)
	if relationID == "" {
		return nil, fmt.Errorf("relation_id is required")
	}
	data, err := s.db.Get([]byte(kgRelationPrefix + relationID))
	if err != nil {
		return nil, fmt.Errorf("relation not found: %s", relationID)
	}
	var rel KGRelation
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("decode relation %s: %w", relationID, err)
	}
	return &rel, nil
}

func (s *KGGraphStore) UpdateRelation(ctx context.Context, relationID string, update *KGRelationUpdate) (*KGRelation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if update == nil {
		return nil, fmt.Errorf("relation update is required")
	}
	rel, err := s.GetRelation(ctx, relationID)
	if err != nil {
		return nil, err
	}
	if update.Target != nil {
		rel.Target = strings.TrimSpace(*update.Target)
	}
	if update.RelationType != nil {
		rel.RelationType = strings.TrimSpace(*update.RelationType)
	}
	if update.Direction != nil {
		rel.Direction = normalizeRelationDirection(*update.Direction)
	}
	if update.Confidence != nil {
		rel.Confidence = *update.Confidence
	}
	if update.Evidence != nil {
		rel.Evidence = strings.TrimSpace(*update.Evidence)
	}
	if update.SourceKind != nil {
		rel.SourceKind = strings.TrimSpace(*update.SourceKind)
	}
	if update.SourceRefs != nil {
		rel.SourceRefs = update.SourceRefs
	}
	if update.Status != nil {
		rel.Status = normalizeRelationStatus(*update.Status)
	}
	if update.Metadata != nil {
		rel.Metadata = cloneStringMap(update.Metadata)
	}
	if update.Attributes != nil {
		rel.Attributes = cloneStringMap(update.Attributes)
	}
	rel.UpdatedAt = time.Now().UTC()
	rel.Revision++
	if err := s.ValidateRelation(ctx, rel); err != nil {
		return nil, err
	}
	if err := s.putRelation(rel); err != nil {
		return nil, err
	}
	return rel, s.appendMutation("update", "relation", rel.RelationID, update.UpdatedBy, rel.Revision)
}

func (s *KGGraphStore) DeleteRelation(ctx context.Context, relationID string, actor ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rel, err := s.GetRelation(ctx, relationID)
	if err != nil {
		return err
	}
	rel.Status = KGRelationStatusDeleted
	rel.UpdatedAt = time.Now().UTC()
	rel.Revision++
	if err := s.putRelation(rel); err != nil {
		return err
	}
	by := ""
	if len(actor) > 0 {
		by = actor[0]
	}
	return s.appendMutation("delete", "relation", rel.RelationID, by, rel.Revision)
}

func (s *KGGraphStore) QueryRelations(ctx context.Context, query *KGRelationQuery) ([]KGRelation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if query == nil {
		query = &KGRelationQuery{}
	}
	if query.Source != "" {
		if resolved, _, err := s.ResolveEntity(ctx, query.Source); err == nil {
			queryCopy := *query
			queryCopy.Source = resolved
			query = &queryCopy
		}
	}
	if query.Target != "" {
		if resolved, _, err := s.ResolveEntity(ctx, query.Target); err == nil {
			queryCopy := *query
			queryCopy.Target = resolved
			query = &queryCopy
		}
	}
	if query.RelationID != "" {
		rel, err := s.GetRelation(ctx, query.RelationID)
		if err != nil {
			return nil, err
		}
		if relationMatches(*rel, *query) {
			return []KGRelation{*rel}, nil
		}
		return []KGRelation{}, nil
	}
	ids, indexed, err := s.relationIDsForQuery(ctx, *query)
	if err != nil {
		return nil, err
	}
	var keys []string
	if !indexed {
		keys, err = s.db.Keys(kgRelationPrefix + "*")
		if err != nil {
			return nil, err
		}
		ids = make([]string, 0, len(keys))
		for _, key := range keys {
			ids = append(ids, strings.TrimPrefix(key, kgRelationPrefix))
		}
	}
	relations := make([]KGRelation, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rel, err := s.GetRelation(ctx, id)
		if err != nil {
			continue
		}
		if relationMatches(*rel, *query) {
			relations = append(relations, *rel)
			if query.Limit > 0 && len(relations) >= query.Limit {
				break
			}
		}
	}
	sort.Slice(relations, func(i, j int) bool {
		if relations[i].CreatedAt.Equal(relations[j].CreatedAt) {
			return relations[i].RelationID < relations[j].RelationID
		}
		return relations[i].CreatedAt.Before(relations[j].CreatedAt)
	})
	return relations, nil
}

func (s *KGGraphStore) CreateOntology(ctx context.Context, ontology *KGOntology) (*KGOntology, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ontology == nil {
		return nil, fmt.Errorf("ontology is required")
	}
	name := strings.TrimSpace(ontology.Name)
	if name == "" {
		return nil, fmt.Errorf("ontology name is required")
	}
	result := ValidateOntologyDefinition(ontology)
	if !result.Valid {
		return nil, fmt.Errorf("invalid ontology: %s", strings.Join(result.Errors, "; "))
	}
	now := time.Now().UTC()
	cp := *ontology
	cp.Name = name
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	data, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}
	if err := s.db.Put([]byte(kgOntologyPrefix+name), data); err != nil {
		return nil, err
	}
	return &cp, s.appendMutation("apply", "ontology", name, "", 1)
}

func (s *KGGraphStore) GetOntology(ctx context.Context, name string) (*KGOntology, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	data, err := s.db.Get([]byte(kgOntologyPrefix + name))
	if err != nil {
		return defaultKGOntology(), nil
	}
	var ontology KGOntology
	if err := json.Unmarshal(data, &ontology); err != nil {
		return nil, fmt.Errorf("decode ontology %s: %w", name, err)
	}
	return &ontology, nil
}

func (s *KGGraphStore) ValidateRelation(ctx context.Context, rel *KGRelation) error {
	if rel == nil {
		return fmt.Errorf("relation is required")
	}
	if strings.TrimSpace(rel.Source) == "" || strings.TrimSpace(rel.Target) == "" || strings.TrimSpace(rel.RelationType) == "" {
		return fmt.Errorf("source, target, and relation_type are required")
	}
	ontology, err := s.GetOntology(ctx, "default")
	if err != nil {
		return err
	}
	rule, ok := ontology.RelationTypes[rel.RelationType]
	if !ok {
		return nil
	}
	if rule.Direction != "" && rule.Direction != KGRelationDirectionBoth && normalizeRelationDirection(rel.Direction) != rule.Direction {
		return fmt.Errorf("relation %s must use direction %s", rel.RelationType, rule.Direction)
	}
	sourceType := nodeTypeFromID(rel.Source)
	targetType := nodeTypeFromID(rel.Target)
	if !typeAllowed(sourceType, rule.AllowedSources) {
		return fmt.Errorf("source type %q not allowed for relation %s", sourceType, rel.RelationType)
	}
	if !typeAllowed(targetType, rule.AllowedTargets) {
		return fmt.Errorf("target type %q not allowed for relation %s", targetType, rel.RelationType)
	}
	for _, field := range rule.RequiredFields {
		switch field {
		case "evidence":
			if strings.TrimSpace(rel.Evidence) == "" {
				return fmt.Errorf("relation %s requires evidence", rel.RelationType)
			}
		case "source_kind":
			if strings.TrimSpace(rel.SourceKind) == "" {
				return fmt.Errorf("relation %s requires source_kind", rel.RelationType)
			}
		case "created_by":
			if strings.TrimSpace(rel.CreatedBy) == "" {
				return fmt.Errorf("relation %s requires created_by", rel.RelationType)
			}
		}
	}
	if rule.MaxOutgoingPerSource > 0 {
		existing, err := s.QueryRelations(ctx, &KGRelationQuery{Source: rel.Source, RelationTypes: []string{rel.RelationType}})
		if err != nil {
			return err
		}
		count := 0
		for _, current := range existing {
			if current.RelationID != rel.RelationID {
				count++
			}
		}
		if count >= rule.MaxOutgoingPerSource {
			return fmt.Errorf("relation %s exceeds max outgoing cardinality for %s", rel.RelationType, rel.Source)
		}
	}
	if rule.MaxIncomingPerTarget > 0 {
		existing, err := s.QueryRelations(ctx, &KGRelationQuery{Target: rel.Target, RelationTypes: []string{rel.RelationType}})
		if err != nil {
			return err
		}
		count := 0
		for _, current := range existing {
			if current.RelationID != rel.RelationID {
				count++
			}
		}
		if count >= rule.MaxIncomingPerTarget {
			return fmt.Errorf("relation %s exceeds max incoming cardinality for %s", rel.RelationType, rel.Target)
		}
	}
	return nil
}

func (s *KGGraphStore) QueryGraph(ctx context.Context, query *KGGraphQuery) (*KGGraphResponse, error) {
	start := time.Now()
	if query == nil {
		query = &KGGraphQuery{}
	}
	depth := query.Depth
	if depth <= 0 {
		depth = 1
	}
	if depth > 16 {
		depth = 16
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 1000
	}
	nodes := map[string]KGGraphNode{}
	relations := map[string]KGRelation{}
	if len(query.SeedIDs) == 0 {
		all, err := s.QueryRelations(ctx, relationQueryFromGraph(query, limit))
		if err != nil {
			return nil, err
		}
		for _, rel := range all {
			addRelationToGraph(nodes, relations, rel)
		}
		return graphResponseFromMaps(nodes, relations, start), nil
	}
	frontier := make(map[string]struct{}, len(query.SeedIDs))
	for _, id := range query.SeedIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if resolved, _, err := s.ResolveEntity(ctx, id); err == nil {
			id = resolved
		}
		frontier[id] = struct{}{}
		nodes[id] = KGGraphNode{ID: id, NodeType: nodeTypeFromID(id)}
	}
	seenAtDepth := map[string]int{}
	for d := 0; d < depth && len(frontier) > 0 && len(relations) < limit; d++ {
		next := map[string]struct{}{}
		for id := range frontier {
			if seenAtDepth[id] > 0 && seenAtDepth[id] <= d {
				continue
			}
			seenAtDepth[id] = d + 1
			candidates, err := s.relationsForNode(ctx, id, query)
			if err != nil {
				return nil, err
			}
			for _, rel := range candidates {
				if len(relations) >= limit {
					break
				}
				if _, ok := relations[rel.RelationID]; ok {
					continue
				}
				addRelationToGraph(nodes, relations, rel)
				if rel.Source == id {
					next[rel.Target] = struct{}{}
				}
				if rel.Target == id {
					next[rel.Source] = struct{}{}
				}
			}
		}
		frontier = next
	}
	return graphResponseFromMaps(nodes, relations, start), nil
}

func (s *KGGraphStore) ShortestPath(ctx context.Context, source, target string, query *KGGraphQuery) (*KGGraphPath, error) {
	source = strings.TrimSpace(source)
	target = strings.TrimSpace(target)
	if source == "" || target == "" {
		return nil, fmt.Errorf("source and target are required")
	}
	if resolved, _, err := s.ResolveEntity(ctx, source); err == nil {
		source = resolved
	}
	if resolved, _, err := s.ResolveEntity(ctx, target); err == nil {
		target = resolved
	}
	if source == target {
		return &KGGraphPath{Nodes: []string{source}}, nil
	}
	if query == nil {
		query = &KGGraphQuery{}
	}
	maxDepth := query.Depth
	if maxDepth <= 0 {
		maxDepth = 8
	}
	queue := []string{source}
	parentNode := map[string]string{source: ""}
	parentRel := map[string]KGRelation{}
	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		levelSize := len(queue)
		for i := 0; i < levelSize; i++ {
			node := queue[0]
			queue = queue[1:]
			neighbors, err := s.relationsForNode(ctx, node, query)
			if err != nil {
				return nil, err
			}
			for _, rel := range neighbors {
				next := rel.Target
				if next == node {
					next = rel.Source
				}
				if _, seen := parentNode[next]; seen {
					continue
				}
				parentNode[next] = node
				parentRel[next] = rel
				if next == target {
					return buildPath(source, target, parentNode, parentRel), nil
				}
				queue = append(queue, next)
			}
		}
	}
	return nil, fmt.Errorf("no path found from %s to %s", source, target)
}

func (s *KGGraphStore) GraphMetrics(ctx context.Context, query *KGRelationQuery) (*KGGraphMetrics, error) {
	relations, err := s.QueryRelations(ctx, query)
	if err != nil {
		return nil, err
	}
	nodes := map[string]struct{}{}
	metrics := &KGGraphMetrics{
		RelationCount:   len(relations),
		DegreeByNode:    map[string]int{},
		OutDegreeByNode: map[string]int{},
		InDegreeByNode:  map[string]int{},
	}
	for _, rel := range relations {
		nodes[rel.Source] = struct{}{}
		nodes[rel.Target] = struct{}{}
		metrics.DegreeByNode[rel.Source]++
		metrics.DegreeByNode[rel.Target]++
		metrics.OutDegreeByNode[rel.Source]++
		metrics.InDegreeByNode[rel.Target]++
	}
	metrics.NodeCount = len(nodes)
	return metrics, nil
}

func (s *KGGraphStore) ListMutationLog(ctx context.Context, limit int) ([]KGMutationLogRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := s.db.Keys(kgMutationPrefix + "*")
	if err != nil {
		return nil, err
	}
	records := make([]KGMutationLogRecord, 0, len(keys))
	for _, key := range keys {
		data, err := s.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var record KGMutationLogRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.Before(records[j].CreatedAt) })
	if limit > 0 && len(records) > limit {
		records = records[len(records)-limit:]
	}
	return records, nil
}

func (s *KGGraphStore) ConnectedComponents(ctx context.Context, query *KGGraphQuery) ([][]string, error) {
	graph, err := s.QueryGraph(ctx, query)
	if err != nil {
		return nil, err
	}
	adj := map[string][]string{}
	for _, node := range graph.Nodes {
		adj[node.ID] = nil
	}
	for _, rel := range graph.Relations {
		adj[rel.Source] = append(adj[rel.Source], rel.Target)
		adj[rel.Target] = append(adj[rel.Target], rel.Source)
	}
	visited := map[string]bool{}
	components := [][]string{}
	for node := range adj {
		if visited[node] {
			continue
		}
		stack := []string{node}
		visited[node] = true
		component := []string{}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			component = append(component, current)
			for _, next := range adj[current] {
				if !visited[next] {
					visited[next] = true
					stack = append(stack, next)
				}
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	sort.Slice(components, func(i, j int) bool {
		if len(components[i]) == len(components[j]) {
			return strings.Join(components[i], "\x00") < strings.Join(components[j], "\x00")
		}
		return len(components[i]) > len(components[j])
	})
	return components, nil
}

func ValidateOntologyDefinition(ontology *KGOntology) KGOntologyValidationResult {
	result := KGOntologyValidationResult{Valid: true}
	if ontology == nil {
		return KGOntologyValidationResult{Valid: false, Errors: []string{"ontology is required"}}
	}
	if strings.TrimSpace(ontology.Name) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "name is required")
	}
	for name, rel := range ontology.RelationTypes {
		if strings.TrimSpace(name) == "" {
			result.Valid = false
			result.Errors = append(result.Errors, "relation type name is required")
		}
		if rel.Direction != "" && rel.Direction != KGRelationDirectionOut && rel.Direction != KGRelationDirectionIn && rel.Direction != KGRelationDirectionBoth {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("relation %s has invalid direction %s", name, rel.Direction))
		}
		if rel.MaxOutgoingPerSource < 0 || rel.MaxIncomingPerTarget < 0 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("relation %s has negative cardinality", name))
		}
	}
	for name, taxonomy := range ontology.Taxonomies {
		if strings.TrimSpace(name) == "" {
			result.Valid = false
			result.Errors = append(result.Errors, "taxonomy name is required")
		}
		for termID, term := range taxonomy.Terms {
			if strings.TrimSpace(termID) == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("taxonomy %s has empty term id", name))
				continue
			}
			if strings.TrimSpace(term.ID) != "" && term.ID != termID {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("taxonomy %s term %s has mismatched id %s", name, termID, term.ID))
			}
			if term.Parent != "" {
				if _, ok := taxonomy.Terms[term.Parent]; !ok {
					result.Valid = false
					result.Errors = append(result.Errors, fmt.Sprintf("taxonomy %s term %s references missing parent %s", name, termID, term.Parent))
				}
			}
		}
	}
	return result
}

func (s *KGGraphStore) putRelation(rel *KGRelation) error {
	data, err := json.Marshal(rel)
	if err != nil {
		return err
	}
	var existing *KGRelation
	if current, err := s.GetRelation(context.Background(), rel.RelationID); err == nil {
		existing = current
	}
	if err := s.db.Put([]byte(kgRelationPrefix+rel.RelationID), data); err != nil {
		return err
	}
	if existing != nil {
		if err := s.deleteRelationIndexes(existing); err != nil {
			return err
		}
	}
	return s.putRelationIndexes(rel)
}

func (s *KGGraphStore) appendMutation(action, entity, entityID, actor string, revision int64) error {
	now := time.Now().UTC()
	id := stableMutationID(action, entity, entityID, revision, now)
	record := KGMutationLogRecord{
		MutationID: id,
		Action:     action,
		Entity:     entity,
		EntityID:   entityID,
		CreatedAt:  now,
		Actor:      actor,
		Revision:   revision,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(kgMutationPrefix+id), data)
}

func (s *KGGraphStore) relationsForNode(ctx context.Context, nodeID string, query *KGGraphQuery) ([]KGRelation, error) {
	if query == nil {
		query = &KGGraphQuery{}
	}
	perNodeLimit := 0
	if query.Limit > 0 {
		perNodeLimit = query.Limit
	}
	base := relationQueryFromGraph(query, perNodeLimit)
	direction := normalizeRelationDirection(query.Direction)
	switch direction {
	case KGRelationDirectionOut:
		base.Source = nodeID
		return s.QueryRelations(ctx, base)
	case KGRelationDirectionIn:
		base.Target = nodeID
		return s.QueryRelations(ctx, base)
	default:
		outgoing := *base
		outgoing.Source = nodeID
		incoming := *base
		incoming.Target = nodeID
		out, err := s.QueryRelations(ctx, &outgoing)
		if err != nil {
			return nil, err
		}
		in, err := s.QueryRelations(ctx, &incoming)
		if err != nil {
			return nil, err
		}
		seen := make(map[string]struct{}, len(out)+len(in))
		merged := make([]KGRelation, 0, len(out)+len(in))
		for _, rel := range out {
			seen[rel.RelationID] = struct{}{}
			merged = append(merged, rel)
		}
		for _, rel := range in {
			if _, ok := seen[rel.RelationID]; ok {
				continue
			}
			merged = append(merged, rel)
		}
		sort.Slice(merged, func(i, j int) bool {
			if merged[i].CreatedAt.Equal(merged[j].CreatedAt) {
				return merged[i].RelationID < merged[j].RelationID
			}
			return merged[i].CreatedAt.Before(merged[j].CreatedAt)
		})
		return merged, nil
	}
}

func (s *KGGraphStore) putRelationIndexes(rel *KGRelation) error {
	if err := s.db.Put([]byte(kgRelationIdxMeta), []byte("1")); err != nil {
		return err
	}
	for _, key := range relationIndexKeys(rel) {
		if err := s.addRelationIDToIndex(key, rel.RelationID); err != nil {
			return err
		}
	}
	return nil
}

func (s *KGGraphStore) deleteRelationIndexes(rel *KGRelation) error {
	for _, key := range relationIndexKeys(rel) {
		if err := s.removeRelationIDFromIndex(key, rel.RelationID); err != nil {
			return err
		}
	}
	return nil
}

func relationIndexKeys(rel *KGRelation) []string {
	if rel == nil || rel.RelationID == "" {
		return nil
	}
	keys := []string{
		relationIndexKey(kgRelationSrcIdx, rel.Source),
		relationIndexKey(kgRelationTgtIdx, rel.Target),
		relationIndexKey(kgRelationTypeIdx, rel.RelationType),
		relationIndexKey(kgRelationStatIdx, string(normalizeRelationStatus(rel.Status))),
	}
	if rel.SourceKind != "" {
		keys = append(keys, relationIndexKey(kgRelationKindIdx, rel.SourceKind))
	}
	return keys
}

func relationIndexKey(prefix, value string) string {
	return prefix + encodeRelationIndexSegment(value)
}

func encodeRelationIndexSegment(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func relationIDFromIndexKey(key string) string {
	idx := strings.LastIndexByte(key, ':')
	if idx < 0 || idx+1 >= len(key) {
		return ""
	}
	return key[idx+1:]
}

func (s *KGGraphStore) relationIDsForQuery(ctx context.Context, query KGRelationQuery) ([]string, bool, error) {
	var sets [][]string
	addSet := func(ids []string) {
		sets = append(sets, ids)
	}
	hasEndpoint := query.Source != "" || query.Target != ""
	if query.Source != "" {
		ids, err := s.relationIDsFromIndex(ctx, kgRelationSrcIdx, query.Source)
		if err != nil {
			return nil, false, err
		}
		addSet(ids)
	}
	if query.Target != "" {
		ids, err := s.relationIDsFromIndex(ctx, kgRelationTgtIdx, query.Target)
		if err != nil {
			return nil, false, err
		}
		addSet(ids)
	}
	// Endpoint adjacency is the most selective path for graph traversal.
	// Hydrated relation filtering is cheaper than scanning broad type/status
	// indexes such as "references" for every frontier node.
	if !hasEndpoint && len(query.RelationTypes) > 0 {
		typeIDs := make([]string, 0)
		for _, relationType := range query.RelationTypes {
			ids, err := s.relationIDsFromIndex(ctx, kgRelationTypeIdx, relationType)
			if err != nil {
				return nil, false, err
			}
			typeIDs = mergeSortedUniqueStrings(typeIDs, ids)
		}
		addSet(typeIDs)
	}
	if !hasEndpoint && query.SourceKind != "" {
		ids, err := s.relationIDsFromIndex(ctx, kgRelationKindIdx, query.SourceKind)
		if err != nil {
			return nil, false, err
		}
		addSet(ids)
	}
	if !hasEndpoint && query.Status != "" {
		ids, err := s.relationIDsFromIndex(ctx, kgRelationStatIdx, string(normalizeRelationStatus(query.Status)))
		if err != nil {
			return nil, false, err
		}
		addSet(ids)
	}
	if len(sets) == 0 {
		return nil, false, nil
	}
	ids := sets[0]
	for _, set := range sets[1:] {
		ids = intersectSortedStrings(ids, set)
		if len(ids) == 0 {
			break
		}
	}
	if len(ids) == 0 {
		available, err := s.relationIndexAvailable(ctx)
		if err != nil {
			return nil, false, err
		}
		if !available {
			return nil, false, nil
		}
	}
	return ids, true, nil
}

func (s *KGGraphStore) relationIDsFromIndex(ctx context.Context, prefix, value string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indexKey := relationIndexKey(prefix, value)
	data, err := s.db.Get([]byte(indexKey))
	if err == nil {
		var ids []string
		if json.Unmarshal(data, &ids) == nil {
			sort.Strings(ids)
			return uniqueSortedStrings(ids), nil
		}
	}
	if (prefix == kgRelationSrcIdx || prefix == kgRelationTgtIdx) && err != nil {
		available, availableErr := s.relationIndexAvailable(ctx)
		if availableErr != nil {
			return nil, availableErr
		}
		if available {
			return nil, nil
		}
	}
	// Compatibility for stores created before relation indexes were compacted:
	// older index entries used one key per relation under the same prefix.
	keys, err := s.db.Keys(indexKey + ":*")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		if id := relationIDFromIndexKey(key); id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return uniqueSortedStrings(ids), nil
}

func (s *KGGraphStore) addRelationIDToIndex(key, relationID string) error {
	if key == "" || relationID == "" {
		return nil
	}
	if isBroadRelationIndexKey(key) {
		return s.db.Put([]byte(key+":"+relationID), []byte("1"))
	}
	ids := []string{}
	if data, err := s.db.Get([]byte(key)); err == nil {
		_ = json.Unmarshal(data, &ids)
	}
	for _, id := range ids {
		if id == relationID {
			return nil
		}
	}
	ids = append(ids, relationID)
	sort.Strings(ids)
	data, err := json.Marshal(uniqueSortedStrings(ids))
	if err != nil {
		return err
	}
	return s.db.Put([]byte(key), data)
}

func isBroadRelationIndexKey(key string) bool {
	return strings.HasPrefix(key, kgRelationTypeIdx) ||
		strings.HasPrefix(key, kgRelationKindIdx) ||
		strings.HasPrefix(key, kgRelationStatIdx)
}

func (s *KGGraphStore) removeRelationIDFromIndex(key, relationID string) error {
	if key == "" || relationID == "" {
		return nil
	}
	if isBroadRelationIndexKey(key) {
		_ = s.db.Delete([]byte(key + ":" + relationID))
		return nil
	}
	data, err := s.db.Get([]byte(key))
	if err != nil {
		_ = s.db.Delete([]byte(key + ":" + relationID))
		return nil
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return nil
	}
	out := ids[:0]
	for _, id := range ids {
		if id != relationID {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		_ = s.db.Delete([]byte(key + ":" + relationID))
		return s.db.Delete([]byte(key))
	}
	sort.Strings(out)
	encoded, err := json.Marshal(uniqueSortedStrings(out))
	if err != nil {
		return err
	}
	_ = s.db.Delete([]byte(key + ":" + relationID))
	return s.db.Put([]byte(key), encoded)
}

func (s *KGGraphStore) relationIndexAvailable(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := s.db.Get([]byte(kgRelationIdxMeta))
	return err == nil, nil
}

func (s *KGGraphStore) RebuildIndexes(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	keys, err := s.db.Keys(kgRelationPrefix + "*")
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := s.db.Put([]byte(kgRelationIdxMeta), []byte("1")); err != nil {
			return err
		}
	}
	for _, key := range keys {
		data, err := s.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var rel KGRelation
		if json.Unmarshal(data, &rel) != nil {
			continue
		}
		if err := s.putRelationIndexes(&rel); err != nil {
			return err
		}
	}
	return nil
}

func relationQueryFromGraph(query *KGGraphQuery, limit int) *KGRelationQuery {
	if query == nil {
		return &KGRelationQuery{Limit: limit}
	}
	return &KGRelationQuery{
		RelationTypes: query.RelationTypes,
		Direction:     query.Direction,
		MinConfidence: query.MinConfidence,
		SourceKind:    query.SourceKind,
		Limit:         limit,
	}
}

func relationMatches(rel KGRelation, query KGRelationQuery) bool {
	if !query.IncludeDeleted && normalizeRelationStatus(rel.Status) == KGRelationStatusDeleted {
		return false
	}
	if query.Status != "" && normalizeRelationStatus(rel.Status) != query.Status {
		return false
	}
	if query.Source != "" && rel.Source != query.Source {
		return false
	}
	if query.Target != "" && rel.Target != query.Target {
		return false
	}
	if len(query.RelationTypes) > 0 && !containsString(query.RelationTypes, rel.RelationType) {
		return false
	}
	if query.Direction != "" && query.Direction != KGRelationDirectionBoth && normalizeRelationDirection(rel.Direction) != query.Direction {
		return false
	}
	if query.MinConfidence > 0 && rel.Confidence < query.MinConfidence {
		return false
	}
	if query.SourceKind != "" && rel.SourceKind != query.SourceKind {
		return false
	}
	return true
}

func addRelationToGraph(nodes map[string]KGGraphNode, relations map[string]KGRelation, rel KGRelation) {
	if _, ok := nodes[rel.Source]; !ok {
		nodes[rel.Source] = KGGraphNode{ID: rel.Source, NodeType: nodeTypeFromID(rel.Source)}
	}
	if _, ok := nodes[rel.Target]; !ok {
		nodes[rel.Target] = KGGraphNode{ID: rel.Target, NodeType: nodeTypeFromID(rel.Target)}
	}
	relations[rel.RelationID] = rel
}

func graphResponseFromMaps(nodes map[string]KGGraphNode, relations map[string]KGRelation, start time.Time) *KGGraphResponse {
	nodeList := make([]KGGraphNode, 0, len(nodes))
	for _, node := range nodes {
		nodeList = append(nodeList, node)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID < nodeList[j].ID })
	relationList := make([]KGRelation, 0, len(relations))
	for _, rel := range relations {
		relationList = append(relationList, rel)
	}
	sort.Slice(relationList, func(i, j int) bool { return relationList[i].RelationID < relationList[j].RelationID })
	return &KGGraphResponse{
		Nodes:       nodeList,
		Relations:   relationList,
		QueryTimeMs: time.Since(start).Milliseconds(),
	}
}

func buildPath(source, target string, parentNode map[string]string, parentRel map[string]KGRelation) *KGGraphPath {
	nodes := []string{target}
	relations := []KGRelation{}
	for current := target; current != source; {
		rel := parentRel[current]
		relations = append([]KGRelation{rel}, relations...)
		current = parentNode[current]
		nodes = append([]string{current}, nodes...)
	}
	return &KGGraphPath{Nodes: nodes, Relations: relations}
}

func defaultKGOntology() *KGOntology {
	now := time.Now().UTC()
	return &KGOntology{
		Name:          "default",
		Version:       "permissive",
		NodeTypes:     map[string]KGOntologyNodeType{},
		RelationTypes: map[string]KGOntologyRelationType{},
		Taxonomies:    map[string]KGOntologyTaxonomy{},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func stableRelationID(source, relationType, target, sourceKind string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{source, relationType, target, sourceKind}, "\x00")))
	return "rel-" + hex.EncodeToString(h[:12])
}

func stableMutationID(action, entity, entityID string, revision int64, t time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", action, entity, entityID, revision, t.UnixNano())))
	return "mut-" + hex.EncodeToString(h[:12])
}

func normalizeRelationDirection(direction KGRelationDirection) KGRelationDirection {
	switch direction {
	case KGRelationDirectionIn, KGRelationDirectionOut, KGRelationDirectionBoth:
		return direction
	default:
		return KGRelationDirectionOut
	}
}

func normalizeRelationStatus(status KGRelationStatus) KGRelationStatus {
	switch status {
	case KGRelationStatusPending, KGRelationStatusDeleted, KGRelationStatusActive:
		return status
	default:
		return KGRelationStatusActive
	}
}

func nodeTypeFromID(id string) string {
	for _, sep := range []string{":", "/"} {
		if idx := strings.Index(id, sep); idx > 0 {
			return id[:idx]
		}
	}
	return ""
}

func typeAllowed(nodeType string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, item := range allowed {
		item = strings.TrimSpace(item)
		if item == "*" || item == nodeType {
			return true
		}
	}
	return false
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

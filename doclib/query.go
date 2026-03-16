package doclib

import (
	"encoding/json"
	"strings"
	"time"
)

// DocumentFilter defines criteria for searching documents.
type DocumentFilter struct {
	UnitID              string
	DeptID              string
	CompanyID           string
	Tags                []string
	Status              DocumentStatus
	ClassificationLevel ClassificationLevel
	DocType             string
	CreatedAfter        time.Time
	CreatedBefore       time.Time
	OwnerUserID         string
	FullText            string
	CustomMetadata      map[string]string
	Limit               int
	Offset              int
	SortBy              string
	// RequesterID is used to filter results to documents the user can read.
	RequesterID string
}

// QueryDocuments scans all doc:meta:* keys, applies filter predicates, and returns
// only documents the requester has read access to.
func (m *DocManager) QueryDocuments(f DocumentFilter) ([]*DocumentMeta, error) {
	keys, err := m.db.Keys(docMetaPrefix + "*")
	if err != nil {
		return nil, err
	}

	var results []*DocumentMeta
	for _, k := range keys {
		b, err := m.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var meta DocumentMeta
		if err := json.Unmarshal(b, &meta); err != nil {
			continue
		}

		// Apply filter predicates.
		if !matchFilter(&meta, f) {
			continue
		}

		// Access control: only include documents the requester can read.
		if f.RequesterID != "" && !m.CanAccess(f.RequesterID, meta.DocID, "read") {
			continue
		}

		results = append(results, &meta)
	}

	// Pagination.
	total := len(results)
	if f.Offset > total {
		return []*DocumentMeta{}, nil
	}
	results = results[f.Offset:]
	if f.Limit > 0 && len(results) > f.Limit {
		results = results[:f.Limit]
	}

	return results, nil
}

// FindRelated returns documents related to the given docID by overlapping tags,
// same unit, or same department. Excludes the source document itself.
func (m *DocManager) FindRelated(docID, requesterID string, limit int) ([]*DocumentMeta, error) {
	source, err := m.GetDocument(docID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}

	keys, err := m.db.Keys(docMetaPrefix + "*")
	if err != nil {
		return nil, err
	}

	type scored struct {
		meta  *DocumentMeta
		score int
	}
	var candidates []scored

	srcTags := make(map[string]struct{}, len(source.Tags))
	for _, t := range source.Tags {
		srcTags[t] = struct{}{}
	}

	for _, k := range keys {
		b, err := m.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var meta DocumentMeta
		if err := json.Unmarshal(b, &meta); err != nil {
			continue
		}
		if meta.DocID == docID {
			continue
		}
		if requesterID != "" && !m.CanAccess(requesterID, meta.DocID, "read") {
			continue
		}
		score := 0
		if meta.OwnerUnitID != "" && meta.OwnerUnitID == source.OwnerUnitID {
			score += 3
		}
		if meta.OwnerDeptID != "" && meta.OwnerDeptID == source.OwnerDeptID {
			score += 2
		}
		for _, t := range meta.Tags {
			if _, ok := srcTags[t]; ok {
				score += 1
			}
		}
		if score > 0 {
			candidates = append(candidates, scored{meta: &meta, score: score})
		}
	}

	// Sort by score descending (simple selection).
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	var results []*DocumentMeta
	for i := 0; i < len(candidates) && i < limit; i++ {
		results = append(results, candidates[i].meta)
	}
	return results, nil
}

func matchFilter(meta *DocumentMeta, f DocumentFilter) bool {
	if f.UnitID != "" && meta.OwnerUnitID != f.UnitID {
		return false
	}
	if f.DeptID != "" && meta.OwnerDeptID != f.DeptID {
		return false
	}
	if f.CompanyID != "" && meta.OwnerCompanyID != f.CompanyID {
		return false
	}
	if f.Status != "" && meta.Status != f.Status {
		return false
	}
	if f.ClassificationLevel != "" && meta.ClassificationLevel != f.ClassificationLevel {
		return false
	}
	if f.DocType != "" && meta.DocType != f.DocType {
		return false
	}
	if f.OwnerUserID != "" && meta.OwnerUserID != f.OwnerUserID {
		return false
	}
	if !f.CreatedAfter.IsZero() && !meta.CreatedAt.After(f.CreatedAfter) {
		return false
	}
	if !f.CreatedBefore.IsZero() && !meta.CreatedAt.Before(f.CreatedBefore) {
		return false
	}
	// All listed tags must be present.
	if len(f.Tags) > 0 {
		tagSet := make(map[string]struct{}, len(meta.Tags))
		for _, t := range meta.Tags {
			tagSet[t] = struct{}{}
		}
		for _, required := range f.Tags {
			if _, ok := tagSet[required]; !ok {
				return false
			}
		}
	}
	// CustomMetadata equality filter.
	for k, v := range f.CustomMetadata {
		if meta.CustomMetadata[k] != v {
			return false
		}
	}
	// Full-text: simple substring match on title/description.
	if f.FullText != "" {
		needle := strings.ToLower(f.FullText)
		if !strings.Contains(strings.ToLower(meta.Title), needle) &&
			!strings.Contains(strings.ToLower(meta.Description), needle) {
			return false
		}
	}
	return true
}

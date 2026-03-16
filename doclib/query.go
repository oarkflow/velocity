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

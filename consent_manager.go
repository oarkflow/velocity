package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// GrantConsent stores consent for a GDPR data subject.
func (cm *ConsentManager) GrantConsent(ctx context.Context, subjectID string, record ConsentRecord) error {
	if subjectID == "" {
		return fmt.Errorf("subjectID is required")
	}
	if record.ConsentID == "" {
		record.ConsentID = fmt.Sprintf("consent:%s:%d", subjectID, time.Now().UnixNano())
	}
	if record.GrantedAt.IsZero() {
		record.GrantedAt = time.Now()
	}
	record.Active = true

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal consent record: %w", err)
	}

	key := []byte(fmt.Sprintf("gdpr:consent:%s:%s", subjectID, record.ConsentID))
	return cm.db.Put(key, data)
}

// WithdrawConsent marks a consent record as withdrawn.
func (cm *ConsentManager) WithdrawConsent(ctx context.Context, subjectID, consentID string) error {
	if subjectID == "" || consentID == "" {
		return fmt.Errorf("subjectID and consentID are required")
	}

	key := []byte(fmt.Sprintf("gdpr:consent:%s:%s", subjectID, consentID))
	data, err := cm.db.Get(key)
	if err != nil {
		return fmt.Errorf("consent record not found: %w", err)
	}

	var record ConsentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("failed to unmarshal consent record: %w", err)
	}

	now := time.Now()
	record.WithdrawnAt = &now
	record.Active = false

	updated, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal consent record: %w", err)
	}

	return cm.db.Put(key, updated)
}

// ListConsents retrieves all consent records for a subject.
func (cm *ConsentManager) ListConsents(ctx context.Context, subjectID string) ([]ConsentRecord, error) {
	if subjectID == "" {
		return nil, fmt.Errorf("subjectID is required")
	}

	keys, err := cm.db.Keys(fmt.Sprintf("gdpr:consent:%s:*", subjectID))
	if err != nil {
		return nil, err
	}

	records := make([]ConsentRecord, 0)
	for _, key := range keys {
		data, err := cm.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var record ConsentRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// HasActiveConsent checks for an active consent by purpose.
func (cm *ConsentManager) HasActiveConsent(ctx context.Context, subjectID, purpose string) (bool, *ConsentRecord, error) {
	records, err := cm.ListConsents(ctx, subjectID)
	if err != nil {
		return false, nil, err
	}

	for _, record := range records {
		if !record.Active {
			continue
		}
		if record.Purpose == purpose || record.Purpose == "*" {
			return true, &record, nil
		}
	}

	return false, nil, nil
}

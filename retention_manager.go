package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AddPolicy adds or updates a retention policy.
func (rm *RetentionManager) AddPolicy(ctx context.Context, policy RetentionPolicy) error {
	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("policy:%d", time.Now().UnixNano())
	}

	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal retention policy: %w", err)
	}

	key := []byte("retention:policy:" + policy.PolicyID)
	return rm.db.Put(key, data)
}

// ListPolicies retrieves all retention policies.
func (rm *RetentionManager) ListPolicies(ctx context.Context) ([]RetentionPolicy, error) {
	keys, err := rm.db.Keys("retention:policy:*")
	if err != nil {
		return nil, err
	}

	policies := make([]RetentionPolicy, 0)
	for _, key := range keys {
		data, err := rm.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var policy RetentionPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			continue
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// EvaluateRetention checks if data exceeds the retention period.
func (rm *RetentionManager) EvaluateRetention(ctx context.Context, dataType string, dataAge time.Duration) (bool, *RetentionPolicy, error) {
	policies, err := rm.ListPolicies(ctx)
	if err != nil {
		return false, nil, err
	}

	for _, policy := range policies {
		if policy.DataType != "" && policy.DataType != dataType {
			continue
		}
		if policy.RetentionPeriod > 0 && dataAge > policy.RetentionPeriod {
			if hasActiveLegalHold(policy.LegalHolds) {
				return false, &policy, nil
			}
			return true, &policy, nil
		}
	}

	return false, nil, nil
}

// EnforceRetentionActions scans objects and applies retention actions.
func (rm *RetentionManager) EnforceRetentionActions(ctx context.Context) (int, error) {
	// Currently enforcing retention on object storage.
	objects, err := rm.db.ListObjects(ObjectListOptions{Folder: "", Recursive: true, MaxKeys: 10000})
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, obj := range objects {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		dataType := ""
		if rm.db.complianceTagManager != nil {
			if tag := rm.db.complianceTagManager.GetTag(obj.Path); tag != nil {
				dataType = string(tag.DataClass)
			}
		}
		if dataType == "" {
			dataType = obj.ContentType
		}

		age := time.Since(obj.CreatedAt)
		exceeds, policy, err := rm.EvaluateRetention(ctx, dataType, age)

		if err != nil || !exceeds || policy == nil {
			continue
		}

		// Apply retention action using internal APIs
		action := strings.ToLower(policy.DeletionMethod)
		switch action {
		case "archive":
			if err := rm.archiveObject(ctx, obj.Path); err != nil {
				continue
			}
		case "anonymize":
			if err := rm.anonymizeObject(ctx, obj.Path); err != nil {
				continue
			}
		default:
			// Use internal delete to bypass compliance checks
			if err := rm.db.DeleteObjectInternal(obj.Path, "retention_service"); err != nil {
				continue
			}
		}
		processed++
	}

	return processed, nil
}

// StartRetentionScheduler starts periodic enforcement of retention actions.
func (rm *RetentionManager) StartRetentionScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = rm.EnforceRetentionActions(ctx)
			}
		}
	}()
}

func (rm *RetentionManager) archiveObject(ctx context.Context, path string) error {
	// Use internal API to bypass compliance checks
	data, meta, err := rm.db.GetObjectInternal(path, "retention_service")
	if err != nil {
		return err
	}
	archivePath := "archive" + path
	_, err = rm.db.StoreObject(archivePath, meta.ContentType, "retention_service", data, &ObjectOptions{Encrypt: meta.Encrypted, SystemOperation: true})
	if err != nil {
		return err
	}
	return rm.db.DeleteObjectInternal(path, "retention_service")
}

func (rm *RetentionManager) anonymizeObject(ctx context.Context, path string) error {
	// Use internal API to bypass compliance checks
	data, meta, err := rm.db.GetObjectInternal(path, "retention_service")
	if err != nil {
		return err
	}

	masked := data
	if rm.db.complianceTagManager != nil && rm.db.complianceTagManager.maskingEngine != nil {
		class := DataClassConfidential
		if tag := rm.db.complianceTagManager.GetTag(path); tag != nil {
			class = tag.DataClass
		}
		maskedStr := rm.db.complianceTagManager.maskingEngine.MaskString(string(data), class)
		masked = []byte(maskedStr)
	}

	_, err = rm.db.StoreObject(path, meta.ContentType, "retention_service", masked, &ObjectOptions{Encrypt: meta.Encrypted, SystemOperation: true})
	return err
}

// AddLegalHold places a legal hold on a retention policy.
func (rm *RetentionManager) AddLegalHold(ctx context.Context, policyID string, hold LegalHold) error {
	policy, err := rm.getPolicyByID(policyID)
	if err != nil {
		return err
	}

	if hold.HoldID == "" {
		hold.HoldID = fmt.Sprintf("hold:%d", time.Now().UnixNano())
	}
	if hold.PlacedAt.IsZero() {
		hold.PlacedAt = time.Now()
	}
	hold.Active = true

	policy.LegalHolds = append(policy.LegalHolds, hold)
	return rm.AddPolicy(ctx, *policy)
}

// ReleaseLegalHold releases a legal hold.
func (rm *RetentionManager) ReleaseLegalHold(ctx context.Context, policyID, holdID string) error {
	policy, err := rm.getPolicyByID(policyID)
	if err != nil {
		return err
	}

	for i := range policy.LegalHolds {
		if policy.LegalHolds[i].HoldID == holdID {
			policy.LegalHolds[i].Active = false
			break
		}
	}

	return rm.AddPolicy(ctx, *policy)
}

func (rm *RetentionManager) getPolicyByID(policyID string) (*RetentionPolicy, error) {
	data, err := rm.db.Get([]byte("retention:policy:" + policyID))
	if err != nil {
		return nil, fmt.Errorf("retention policy not found: %w", err)
	}
	var policy RetentionPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal retention policy: %w", err)
	}
	return &policy, nil
}

func hasActiveLegalHold(holds []LegalHold) bool {
	for _, hold := range holds {
		if hold.Active {
			if hold.ExpiresAt == nil || time.Now().Before(*hold.ExpiresAt) {
				return true
			}
		}
	}
	return false
}

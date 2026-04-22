package velocity

import (
	"context"
	"time"
)

// AddRetentionPolicy adds or updates a GDPR retention policy.
func (gc *GDPRController) AddRetentionPolicy(ctx context.Context, policy RetentionPolicy) error {
	if gc.retentionMgr == nil {
		return nil
	}
	return gc.retentionMgr.AddPolicy(ctx, policy)
}

// EvaluateRetention checks retention status for a data type and age.
func (gc *GDPRController) EvaluateRetention(ctx context.Context, dataType string, dataAge time.Duration) (bool, *RetentionPolicy, error) {
	if gc.retentionMgr == nil {
		return false, nil, nil
	}
	return gc.retentionMgr.EvaluateRetention(ctx, dataType, dataAge)
}

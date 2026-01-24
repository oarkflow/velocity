package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// LogComplianceOperation logs a compliance operation using existing audit system
func (alm *AuditLogManager) LogComplianceOperation(
	ctx context.Context,
	req *ComplianceOperationRequest,
	result *ComplianceValidationResult,
	durationMs int64,
) error {
	outcome := "success"
	if !result.Allowed {
		outcome = "denied"
	}

	frameworks := make([]ComplianceFramework, 0)
	if result.AppliedTag != nil {
		frameworks = result.AppliedTag.Frameworks
	}

	dataClass := DataClassification("")
	if result.AppliedTag != nil {
		dataClass = result.AppliedTag.DataClass
	}

	event := AuditEvent{
		Timestamp:      time.Now(),
		Actor:          req.Actor,
		Action:         req.Operation,
		Resource:       req.Path,
		Result:         outcome,
		IPAddress:      req.IPAddress,
		Reason:         req.Reason,
		Classification: dataClass,
		ComplianceTags: frameworks,
	}

	return alm.LogEvent(event)
}

// GetComplianceLogs retrieves audit logs with filtering for compliance reporting
func (alm *AuditLogManager) GetComplianceLogs(filter *AuditLogFilter) ([]AuditEvent, error) {
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	// Get all sealed blocks
	allKeys, err := alm.db.Keys("audit:block:*")
	if err != nil {
		return nil, fmt.Errorf("failed to get audit blocks: %w", err)
	}

	events := make([]AuditEvent, 0)
	for _, key := range allKeys {
		data, err := alm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var block ImmutableAuditLog
		if err := json.Unmarshal(data, &block); err != nil {
			continue
		}

		for _, event := range block.Events {
			// Apply filters
			if filter != nil {
				if filter.Actor != "" && event.Actor != filter.Actor {
					continue
				}
				if filter.Action != "" && event.Action != filter.Action {
					continue
				}
				if filter.Outcome != "" && event.Result != filter.Outcome {
					continue
				}
				if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
					continue
				}
				if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
					continue
				}
				if filter.Path != "" && event.Resource != filter.Path {
					continue
				}
			}

			events = append(events, event)
		}
	}

	// Add pending events
	for _, event := range alm.pendingEvents {
		if filter != nil {
			if filter.Actor != "" && event.Actor != filter.Actor {
				continue
			}
			if filter.Action != "" && event.Action != filter.Action {
				continue
			}
			if filter.Outcome != "" && event.Result != filter.Outcome {
				continue
			}
			if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
				continue
			}
			if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
				continue
			}
			if filter.Path != "" && event.Resource != filter.Path {
				continue
			}
		}
		events = append(events, event)
	}

	return events, nil
}

// GetStats generates statistics from audit logs for compliance
func (alm *AuditLogManager) GetStats(ctx context.Context, filter *AuditLogFilter) (*AuditLogStats, error) {
	events, err := alm.GetComplianceLogs(filter)
	if err != nil {
		return nil, err
	}

	stats := &AuditLogStats{
		TotalLogs:     int64(len(events)),
		CommonActions: make(map[string]int64),
	}

	actorMap := make(map[string]*ActorStats)

	for _, event := range events {
		if event.Result == "success" || event.Result == "allowed" {
			stats.AllowedOps++
		} else {
			stats.DeniedOps++
		}

		stats.CommonActions[event.Action]++

		// Track actor stats
		if _, ok := actorMap[event.Actor]; !ok {
			actorMap[event.Actor] = &ActorStats{
				Actor:      event.Actor,
				Violations: make([]string, 0),
			}
		}
		actorMap[event.Actor].TotalOps++
		if event.Result == "denied" {
			actorMap[event.Actor].Denied++
		}
	}

	stats.UniqueActors = len(actorMap)
	if stats.TotalLogs > 0 {
		stats.ViolationRate = float64(stats.DeniedOps) / float64(stats.TotalLogs) * 100
	}

	// Sort top violators
	for _, actor := range actorMap {
		stats.TopViolators = append(stats.TopViolators, *actor)
	}
	// Sort by denied count
	for i := 0; i < len(stats.TopViolators)-1; i++ {
		for j := i + 1; j < len(stats.TopViolators); j++ {
			if stats.TopViolators[i].Denied < stats.TopViolators[j].Denied {
				stats.TopViolators[i], stats.TopViolators[j] =
					stats.TopViolators[j], stats.TopViolators[i]
			}
		}
	}

	// Keep top 10
	if len(stats.TopViolators) > 10 {
		stats.TopViolators = stats.TopViolators[:10]
	}

	return stats, nil
}

// VerifyIntegrity verifies the audit log chain integrity
func (alm *AuditLogManager) VerifyIntegrity(ctx context.Context) error {
	// Use existing VerifyChain method
	return alm.VerifyChain()
}

// AuditLogFilter defines criteria for filtering audit logs
type AuditLogFilter struct {
	Actor     string
	Action    string
	Path      string
	Outcome   string // allowed, denied, success, failure
	StartTime time.Time
	EndTime   time.Time
	Limit     int
}

// AuditLogStats provides statistics about audit logs
type AuditLogStats struct {
	TotalLogs      int64
	AllowedOps     int64
	DeniedOps      int64
	UniqueActors   int
	TopViolators   []ActorStats
	CommonActions  map[string]int64
	ViolationRate  float64
}

// ActorStats represents statistics for an actor
type ActorStats struct {
	Actor      string
	TotalOps   int64
	Denied     int64
	Violations []string
}

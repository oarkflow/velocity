package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// BreakGlassRequest represents emergency access request.
type BreakGlassRequest struct {
	RequestID   string    `json:"request_id"`
	Actor       string    `json:"actor"`
	Reason      string    `json:"reason"`
	Resource    string    `json:"resource"`
	RequestedAt time.Time `json:"requested_at"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	ApprovedBy  string    `json:"approved_by,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	Status      string    `json:"status"` // pending, approved, active, revoked, expired
}

// BreakGlassManager manages emergency access requests.
type BreakGlassManager struct {
	db         *DB
	auditMgr   *AuditLogManager
}

// NewBreakGlassManager creates a new break-glass manager.
func NewBreakGlassManager(db *DB) *BreakGlassManager {
	return &BreakGlassManager{db: db}
}

// SetAuditManager sets audit manager.
func (bg *BreakGlassManager) SetAuditManager(am *AuditLogManager) {
	bg.auditMgr = am
}

// RequestAccess creates a new break-glass request.
func (bg *BreakGlassManager) RequestAccess(ctx context.Context, req *BreakGlassRequest) error {
	if req.RequestID == "" {
		req.RequestID = fmt.Sprintf("breakglass:%d", time.Now().UnixNano())
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now()
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = req.RequestedAt.Add(2 * time.Hour)
	}
	if req.Status == "" {
		req.Status = "pending"
	}

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal break-glass request: %w", err)
	}
	key := []byte("breakglass:request:" + req.RequestID)
	return bg.db.Put(key, data)
}

// ApproveRequest approves a break-glass request.
func (bg *BreakGlassManager) ApproveRequest(ctx context.Context, requestID, approver string) error {
	req, err := bg.getRequest(requestID)
	if err != nil {
		return err
	}

	now := time.Now()
	req.Status = "approved"
	req.ApprovedAt = &now
	req.ApprovedBy = approver

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal break-glass request: %w", err)
	}
	key := []byte("breakglass:request:" + req.RequestID)
	if err := bg.db.Put(key, data); err != nil {
		return err
	}

	if bg.auditMgr != nil {
		_ = bg.auditMgr.LogEvent(AuditEvent{
			Timestamp: time.Now(),
			Actor:     approver,
			Action:    "breakglass_approve",
			Resource:  req.Resource,
			Result:    "success",
			Reason:    req.Reason,
		})
	}

	return nil
}

// IsActive checks whether a request is currently active.
func (bg *BreakGlassManager) IsActive(ctx context.Context, requestID string) (bool, error) {
	req, err := bg.getRequest(requestID)
	if err != nil {
		return false, err
	}

	if req.Status != "approved" {
		return false, nil
	}
	if time.Now().After(req.ExpiresAt) {
		return false, nil
	}
	return true, nil
}

func (bg *BreakGlassManager) getRequest(requestID string) (*BreakGlassRequest, error) {
	data, err := bg.db.Get([]byte("breakglass:request:" + requestID))
	if err != nil {
		return nil, fmt.Errorf("break-glass request not found: %w", err)
	}
	var req BreakGlassRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal break-glass request: %w", err)
	}
	return &req, nil
}

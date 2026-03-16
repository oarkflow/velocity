package doclib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	flowHistoryPrefix = "flow:history:"
)

// FlowEvent represents a single lifecycle transition.
type FlowEvent struct {
	EventID    string         `json:"event_id"`
	DocID      string         `json:"doc_id"`
	FromStatus DocumentStatus `json:"from_status"`
	ToStatus   DocumentStatus `json:"to_status"`
	Actor      string         `json:"actor"`
	Timestamp  time.Time      `json:"timestamp"`
	Comment    string         `json:"comment"`
	IP         string         `json:"ip"`
}

// LifecycleManager handles document status transitions and history.
type LifecycleManager struct {
	db     *velocity.DB
	docMgr *DocManager
	audit  *AuditManager
}

// NewLifecycleManager returns a LifecycleManager.
func NewLifecycleManager(db *velocity.DB, docMgr *DocManager, audit *AuditManager) *LifecycleManager {
	return &LifecycleManager{db: db, docMgr: docMgr, audit: audit}
}

// Transition moves a document from any status to toStatus.
// The caller must hold at least "write" permission on the document.
func (m *LifecycleManager) Transition(docID, actor, ip, comment string, toStatus DocumentStatus) (*DocumentMeta, error) {
	meta, err := m.docMgr.GetDocument(docID)
	if err != nil {
		return nil, err
	}

	// Permission checks per target status.
	requiredPerm := "write"
	switch toStatus {
	case StatusApproved, StatusRejected:
		requiredPerm = "approve"
	case StatusPublished:
		requiredPerm = "publish"
	case StatusArchived:
		requiredPerm = "manage"
	}

	if !m.docMgr.CanAccess(actor, docID, requiredPerm) {
		if m.audit != nil {
			m.audit.Log(DocAccessEvent{
				DocID:     docID,
				Actor:     actor,
				Action:    ActionLifecycleTransition,
				Outcome:   OutcomeDenied,
				IPAddress: ip,
				Detail:    fmt.Sprintf("→%s requires %s permission", toStatus, requiredPerm),
			})
		}
		return nil, ErrAccessDenied
	}

	fromStatus := meta.Status
	event := FlowEvent{
		EventID:    uuid.NewString(),
		DocID:      docID,
		FromStatus: fromStatus,
		ToStatus:   toStatus,
		Actor:      actor,
		Timestamp:  time.Now().UTC(),
		Comment:    comment,
		IP:         ip,
	}

	if err := m.appendEvent(docID, event); err != nil {
		return nil, err
	}

	meta, err = m.docMgr.UpdateDocument(docID, actor, func(d *DocumentMeta) {
		d.Status = toStatus
	})
	if err != nil {
		return nil, err
	}

	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:     docID,
			Actor:     actor,
			Action:    ActionLifecycleTransition,
			Outcome:   OutcomeSuccess,
			IPAddress: ip,
			Detail:    fmt.Sprintf("%s → %s: %s", fromStatus, toStatus, comment),
			Metadata: map[string]string{
				"from_status": string(fromStatus),
				"to_status":   string(toStatus),
				"event_id":    event.EventID,
			},
		})
	}

	return meta, nil
}

// Submit is a convenience wrapper: draft → under_review.
func (m *LifecycleManager) Submit(docID, actor, ip, comment string) (*DocumentMeta, error) {
	return m.Transition(docID, actor, ip, comment, StatusUnderReview)
}

// Approve is a convenience wrapper: under_review → approved.
func (m *LifecycleManager) Approve(docID, actor, ip, comment string) (*DocumentMeta, error) {
	return m.Transition(docID, actor, ip, comment, StatusApproved)
}

// Publish is a convenience wrapper: approved → published.
func (m *LifecycleManager) Publish(docID, actor, ip, comment string) (*DocumentMeta, error) {
	return m.Transition(docID, actor, ip, comment, StatusPublished)
}

// Archive is a convenience wrapper: * → archived.
func (m *LifecycleManager) Archive(docID, actor, ip, comment string) (*DocumentMeta, error) {
	return m.Transition(docID, actor, ip, comment, StatusArchived)
}

// Reject is a convenience wrapper: under_review → rejected.
func (m *LifecycleManager) Reject(docID, actor, ip, comment string) (*DocumentMeta, error) {
	return m.Transition(docID, actor, ip, comment, StatusRejected)
}

// GetHistory returns the full event history for a document.
func (m *LifecycleManager) GetHistory(docID string) ([]FlowEvent, error) {
	return m.loadHistory(docID)
}

// appendEvent loads the current history, appends the new event, and persists.
func (m *LifecycleManager) appendEvent(docID string, event FlowEvent) error {
	history, _ := m.loadHistory(docID) // ignore error — empty is fine
	history = append(history, event)
	b, err := json.Marshal(history)
	if err != nil {
		return fmt.Errorf("marshal history: %w", err)
	}
	return m.db.Put([]byte(flowHistoryPrefix+docID), b)
}

func (m *LifecycleManager) loadHistory(docID string) ([]FlowEvent, error) {
	b, err := m.db.Get([]byte(flowHistoryPrefix + docID))
	if err != nil {
		return []FlowEvent{}, nil
	}
	var history []FlowEvent
	if err := json.Unmarshal(b, &history); err != nil {
		return nil, err
	}
	return history, nil
}

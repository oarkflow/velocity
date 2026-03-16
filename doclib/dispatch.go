package doclib

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	dispatchPrefix = "dispatch:req:"
)

// DispatchStatus tracks the lifecycle of a dispatch.
type DispatchStatus string

const (
	DispatchStatusPending      DispatchStatus = "pending"
	DispatchStatusSent         DispatchStatus = "sent"
	DispatchStatusAcknowledged DispatchStatus = "acknowledged"
	DispatchStatusRecalled     DispatchStatus = "recalled"
)

// RecipientType describes the kind of entity receiving the dispatch.
type RecipientType string

const (
	RecipientService    RecipientType = "service"
	RecipientGovernment RecipientType = "government"
	RecipientBank       RecipientType = "bank"
	RecipientUnit       RecipientType = "unit"
	RecipientExternal   RecipientType = "external"
)

// DispatchRecipient names a single destination.
type DispatchRecipient struct {
	Type       RecipientType `json:"type"`
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Reference  string        `json:"reference,omitempty"` // external reference / case number
	Permissions []string     `json:"permissions"`
}

// DispatchRequest carries inputs for SendDispatch.
type DispatchRequest struct {
	DocID       string              `json:"doc_id"`
	SentBy      string              `json:"sent_by"`
	Recipients  []DispatchRecipient `json:"recipients"`
	Purpose     string              `json:"purpose"`
	CaseRef     string              `json:"case_ref,omitempty"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
	TimeLock    bool                `json:"time_lock,omitempty"`
	LegalNote   string              `json:"legal_note,omitempty"`
	Tags        map[string]string   `json:"tags,omitempty"`
}

// DispatchRecord is stored under dispatch:req:{dispatchID}.
type DispatchRecord struct {
	DispatchID  string              `json:"dispatch_id"`
	DocID       string              `json:"doc_id"`
	EnvelopeID  string              `json:"envelope_id"`
	SentBy      string              `json:"sent_by"`
	SentAt      time.Time           `json:"sent_at"`
	Recipients  []DispatchRecipient `json:"recipients"`
	Purpose     string              `json:"purpose"`
	CaseRef     string              `json:"case_ref,omitempty"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
	LegalNote   string              `json:"legal_note,omitempty"`
	Status      DispatchStatus      `json:"status"`
	AckBy       string              `json:"ack_by,omitempty"`
	AckAt       *time.Time          `json:"ack_at,omitempty"`
	RecalledBy  string              `json:"recalled_by,omitempty"`
	RecalledAt  *time.Time          `json:"recalled_at,omitempty"`
	RecallNote  string              `json:"recall_note,omitempty"`
	Tags        map[string]string   `json:"tags,omitempty"`
}

// DispatchManager handles sealing and dispatching documents to external recipients.
type DispatchManager struct {
	db     *velocity.DB
	docMgr *DocManager
	audit  *AuditManager
}

// NewDispatchManager returns a wired DispatchManager.
func NewDispatchManager(db *velocity.DB, docMgr *DocManager, audit *AuditManager) *DispatchManager {
	return &DispatchManager{db: db, docMgr: docMgr, audit: audit}
}

// SendDispatch seals the document into a Velocity envelope and creates a dispatch record.
// The envelope captures the full payload (object path) plus an access chain custody event,
// making the dispatch tamper-evident and legally binding.
func (m *DispatchManager) SendDispatch(ctx context.Context, req DispatchRequest, ip string) (*DispatchRecord, error) {
	if len(req.Recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one recipient required", ErrInvalidInput)
	}
	meta, err := m.docMgr.GetDocument(req.DocID)
	if err != nil {
		return nil, fmt.Errorf("document %w", ErrNotFound)
	}
	if !m.docMgr.CanAccess(req.SentBy, req.DocID, "read") {
		m.audit.Log(DocAccessEvent{
			DocID:   req.DocID,
			Actor:   req.SentBy,
			Action:  ActionDocDispatched,
			Outcome: OutcomeDenied,
			Detail:  "sender lacks read permission",
			IPAddress: ip,
		})
		return nil, ErrAccessDenied
	}

	// Build recipient labels for the envelope label.
	recipientNames := make([]string, 0, len(req.Recipients))
	for _, r := range req.Recipients {
		recipientNames = append(recipientNames, fmt.Sprintf("%s/%s", r.Type, r.Name))
	}

	// Seal the document into a Velocity envelope.
	envReq := &velocity.EnvelopeRequest{
		Label:         fmt.Sprintf("dispatch:%s → %s", meta.Title, strings.Join(recipientNames, ", ")),
		Type:          velocity.EnvelopeTypeCustodyProof,
		EvidenceClass: string(meta.ClassificationLevel),
		CreatedBy:     req.SentBy,
		CaseReference: req.CaseRef,
		Notes:         req.Purpose,
		Payload: velocity.EnvelopePayload{
			Kind:       "file",
			ObjectPath: meta.ObjectPath,
			Key:        meta.DocID,
			Metadata: map[string]string{
				"doc_id":    meta.DocID,
				"doc_title": meta.Title,
				"doc_type":  meta.DocType,
				"sent_by":   req.SentBy,
				"purpose":   req.Purpose,
			},
		},
		Tags: func() map[string]string {
			t := map[string]string{
				"dispatch_for": strings.Join(recipientNames, ";"),
				"case_ref":     req.CaseRef,
			}
			for k, v := range req.Tags {
				t[k] = v
			}
			return t
		}(),
	}

	if req.TimeLock && req.ExpiresAt != nil {
		envReq.Policies.TimeLock = velocity.TimeLockPolicy{
			Mode:            "absolute",
			UnlockNotBefore: *req.ExpiresAt,
			LegalCondition:  req.LegalNote,
		}
	}

	envelope, err := m.db.CreateEnvelope(ctx, envReq)
	if err != nil {
		return nil, fmt.Errorf("seal envelope: %w", err)
	}

	// Append a custody event noting all recipients.
	for _, r := range req.Recipients {
		_, _ = m.db.AppendCustodyEvent(ctx, envelope.EnvelopeID, &velocity.CustodyEvent{
			Actor:         req.SentBy,
			Action:        "dispatch.sent",
			Location:      fmt.Sprintf("%s:%s", r.Type, r.ID),
			Notes:         fmt.Sprintf("sent to %s (%s) purpose=%s", r.Name, r.Reference, req.Purpose),
			EvidenceState: "dispatched",
		})
	}

	dispatch := &DispatchRecord{
		DispatchID: uuid.NewString(),
		DocID:      req.DocID,
		EnvelopeID: envelope.EnvelopeID,
		SentBy:     req.SentBy,
		SentAt:     time.Now().UTC(),
		Recipients: req.Recipients,
		Purpose:    req.Purpose,
		CaseRef:    req.CaseRef,
		ExpiresAt:  req.ExpiresAt,
		LegalNote:  req.LegalNote,
		Status:     DispatchStatusSent,
		Tags:       req.Tags,
	}

	if err := m.putDispatch(dispatch); err != nil {
		return nil, err
	}

	m.audit.Log(DocAccessEvent{
		DocID:     req.DocID,
		Actor:     req.SentBy,
		Action:    ActionDocDispatched,
		Outcome:   OutcomeSuccess,
		IPAddress: ip,
		Detail:    fmt.Sprintf("envelope=%s recipients=%s", envelope.EnvelopeID, strings.Join(recipientNames, ";")),
		Metadata: map[string]string{
			"dispatch_id": dispatch.DispatchID,
			"envelope_id": envelope.EnvelopeID,
			"case_ref":    req.CaseRef,
		},
	})

	return dispatch, nil
}

// GetDispatch retrieves a dispatch record.
func (m *DispatchManager) GetDispatch(dispatchID string) (*DispatchRecord, error) {
	b, err := m.db.Get([]byte(dispatchPrefix + dispatchID))
	if err != nil {
		return nil, ErrNotFound
	}
	var d DispatchRecord
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ListDispatches returns all dispatch records for a document.
func (m *DispatchManager) ListDispatches(docID string) ([]*DispatchRecord, error) {
	keys, err := m.db.Keys(dispatchPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*DispatchRecord, 0)
	for _, k := range keys {
		b, err := m.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var d DispatchRecord
		if err := json.Unmarshal(b, &d); err != nil {
			continue
		}
		if d.DocID == docID {
			out = append(out, &d)
		}
	}
	return out, nil
}

// AcknowledgeDispatch marks the dispatch acknowledged by the receiving actor.
func (m *DispatchManager) AcknowledgeDispatch(ctx context.Context, dispatchID, actor, ip string) (*DispatchRecord, error) {
	d, err := m.GetDispatch(dispatchID)
	if err != nil {
		return nil, err
	}
	if d.Status == DispatchStatusRecalled {
		return nil, fmt.Errorf("%w: dispatch has been recalled", ErrInvalidInput)
	}
	now := time.Now().UTC()
	d.Status = DispatchStatusAcknowledged
	d.AckBy = actor
	d.AckAt = &now

	_, _ = m.db.AppendCustodyEvent(ctx, d.EnvelopeID, &velocity.CustodyEvent{
		Actor:         actor,
		Action:        "dispatch.acknowledged",
		Notes:         fmt.Sprintf("acknowledged by %s", actor),
		EvidenceState: "acknowledged",
	})

	m.audit.Log(DocAccessEvent{
		DocID:     d.DocID,
		Actor:     actor,
		Action:    ActionDispatchAcknowledged,
		Outcome:   OutcomeSuccess,
		IPAddress: ip,
		Detail:    fmt.Sprintf("dispatch=%s envelope=%s", dispatchID, d.EnvelopeID),
	})

	return d, m.putDispatch(d)
}

// RecallDispatch marks a dispatch recalled (the envelope custody chain records the recall).
func (m *DispatchManager) RecallDispatch(ctx context.Context, dispatchID, recalledBy, note, ip string) (*DispatchRecord, error) {
	d, err := m.GetDispatch(dispatchID)
	if err != nil {
		return nil, err
	}
	if d.Status == DispatchStatusRecalled {
		return nil, fmt.Errorf("%w: already recalled", ErrInvalidInput)
	}
	now := time.Now().UTC()
	d.Status = DispatchStatusRecalled
	d.RecalledBy = recalledBy
	d.RecalledAt = &now
	d.RecallNote = note

	_, _ = m.db.AppendCustodyEvent(ctx, d.EnvelopeID, &velocity.CustodyEvent{
		Actor:         recalledBy,
		Action:        "dispatch.recalled",
		Notes:         note,
		EvidenceState: "recalled",
	})

	m.audit.Log(DocAccessEvent{
		DocID:     d.DocID,
		Actor:     recalledBy,
		Action:    ActionDispatchRecalled,
		Outcome:   OutcomeSuccess,
		IPAddress: ip,
		Detail:    fmt.Sprintf("dispatch=%s note=%s", dispatchID, note),
	})

	return d, m.putDispatch(d)
}

// GetEnvelope returns the full Velocity envelope for a dispatch, including its
// full custody ledger. Only actors who can read the document see this.
func (m *DispatchManager) GetEnvelope(ctx context.Context, dispatchID, actor string) (*velocity.Envelope, error) {
	d, err := m.GetDispatch(dispatchID)
	if err != nil {
		return nil, err
	}
	if !m.docMgr.CanAccess(actor, d.DocID, "read") {
		return nil, ErrAccessDenied
	}
	return m.db.LoadEnvelope(ctx, d.EnvelopeID)
}

func (m *DispatchManager) putDispatch(d *DispatchRecord) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(dispatchPrefix+d.DispatchID), b)
}

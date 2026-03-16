package doclib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	shareReqPrefix = "share:req:"
)

// GrantType describes the target of a share request.
type GrantType string

const (
	GrantTypeUnit    GrantType = "unit"
	GrantTypeDept    GrantType = "dept"
	GrantTypeUser    GrantType = "user"
	GrantTypeCompany GrantType = "company"
)

// ApprovalStatus tracks the state of a share request.
type ApprovalStatus string

const (
	ApprovalPending      ApprovalStatus = "pending"
	ApprovalApproved     ApprovalStatus = "approved"
	ApprovalRejected     ApprovalStatus = "rejected"
	ApprovalAutoApproved ApprovalStatus = "auto_approved"
)

// ShareRequest represents a request to share a document with another entity.
type ShareRequest struct {
	ShareID          string         `json:"share_id"`
	DocID            string         `json:"doc_id"`
	RequestedBy      string         `json:"requested_by"`
	RequestedAt      time.Time      `json:"requested_at"`
	GrantToType      GrantType      `json:"grant_to_type"`
	GrantToID        string         `json:"grant_to_id"`
	Permissions      []string       `json:"permissions"`
	RequiresApproval bool           `json:"requires_approval"`
	ApprovalStatus   ApprovalStatus `json:"approval_status"`
	ApprovedBy       string         `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time     `json:"approved_at,omitempty"`
	ExpiresAt        *time.Time     `json:"expires_at,omitempty"`
	Revoked          bool           `json:"revoked"`
	RevokedBy        string         `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time     `json:"revoked_at,omitempty"`
	Reason           string         `json:"reason,omitempty"`
}

// ShareManager handles creating, approving, rejecting, and revoking shares.
type ShareManager struct {
	db     *velocity.DB
	docMgr *DocManager
	orgMgr *OrgManager
	audit  *AuditManager
}

// NewShareManager returns a ShareManager.
func NewShareManager(db *velocity.DB, docMgr *DocManager, orgMgr *OrgManager, audit *AuditManager) *ShareManager {
	return &ShareManager{db: db, docMgr: docMgr, orgMgr: orgMgr, audit: audit}
}

// CreateShare creates a new share request. Auto-approves when classification or document settings allow.
func (m *ShareManager) CreateShare(docID, requestedBy string, grantType GrantType, grantToID string, perms []string, reason string, expiresAt *time.Time) (*ShareRequest, error) {
	meta, err := m.docMgr.GetDocument(docID)
	if err != nil {
		return nil, fmt.Errorf("document %w", ErrNotFound)
	}
	if !m.docMgr.CanAccess(requestedBy, docID, "write") && meta.OwnerUserID != requestedBy {
		m.logShare(docID, requestedBy, ActionShareCreated, OutcomeDenied, "lacks write permission")
		return nil, ErrAccessDenied
	}

	needsApproval := meta.RequiresShareApproval &&
		meta.ClassificationLevel != ClassPublic &&
		meta.ClassificationLevel != ClassInternal

	status := ApprovalAutoApproved
	if needsApproval {
		status = ApprovalPending
	}

	req := &ShareRequest{
		ShareID:          uuid.NewString(),
		DocID:            docID,
		RequestedBy:      requestedBy,
		RequestedAt:      time.Now().UTC(),
		GrantToType:      grantType,
		GrantToID:        grantToID,
		Permissions:      perms,
		RequiresApproval: needsApproval,
		ApprovalStatus:   status,
		ExpiresAt:        expiresAt,
		Reason:           reason,
	}

	if !needsApproval {
		if err := m.applyGrant(req); err != nil {
			return nil, err
		}
		m.logShare(docID, requestedBy, ActionShareAutoApproved, OutcomeSuccess,
			fmt.Sprintf("auto-approved grant_to=%s/%s", grantType, grantToID))
	} else {
		m.logShare(docID, requestedBy, ActionShareCreated, OutcomeSuccess,
			fmt.Sprintf("pending approval grant_to=%s/%s", grantType, grantToID))
	}

	return req, m.putShare(req)
}

// GetShare retrieves a share request.
func (m *ShareManager) GetShare(shareID string) (*ShareRequest, error) {
	b, err := m.db.Get([]byte(shareReqPrefix + shareID))
	if err != nil {
		return nil, ErrNotFound
	}
	var req ShareRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// ListShares returns all share requests for a document.
func (m *ShareManager) ListShares(docID string) ([]*ShareRequest, error) {
	keys, err := m.db.Keys(shareReqPrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]*ShareRequest, 0)
	for _, k := range keys {
		b, err := m.db.Get([]byte(k))
		if err != nil {
			continue
		}
		var req ShareRequest
		if err := json.Unmarshal(b, &req); err != nil {
			continue
		}
		if req.DocID == docID {
			out = append(out, &req)
		}
	}
	return out, nil
}

// ApproveShare approves a pending share request and applies the ACL grant.
func (m *ShareManager) ApproveShare(shareID, approverID string) (*ShareRequest, error) {
	req, err := m.GetShare(shareID)
	if err != nil {
		return nil, err
	}
	if req.Revoked {
		return nil, ErrRevoked
	}
	if req.ApprovalStatus != ApprovalPending {
		return nil, ErrNotPending
	}
	meta, err := m.docMgr.GetDocument(req.DocID)
	if err != nil {
		return nil, err
	}
	if !m.orgMgr.IsManagerOrHead(approverID, meta.OwnerUnitID) && meta.OwnerUserID != approverID {
		m.logShare(req.DocID, approverID, ActionShareApproved, OutcomeDenied, "not manager or head")
		return nil, ErrAccessDenied
	}

	now := time.Now().UTC()
	req.ApprovalStatus = ApprovalApproved
	req.ApprovedBy = approverID
	req.ApprovedAt = &now

	if err := m.applyGrant(req); err != nil {
		return nil, err
	}
	m.logShare(req.DocID, approverID, ActionShareApproved, OutcomeSuccess,
		fmt.Sprintf("share=%s grant_to=%s/%s", shareID, req.GrantToType, req.GrantToID))

	return req, m.putShare(req)
}

// RejectShare rejects a pending share request.
func (m *ShareManager) RejectShare(shareID, rejectorID, reason string) (*ShareRequest, error) {
	req, err := m.GetShare(shareID)
	if err != nil {
		return nil, err
	}
	if req.Revoked {
		return nil, ErrRevoked
	}
	if req.ApprovalStatus != ApprovalPending {
		return nil, ErrNotPending
	}
	meta, err := m.docMgr.GetDocument(req.DocID)
	if err != nil {
		return nil, err
	}
	if !m.orgMgr.IsManagerOrHead(rejectorID, meta.OwnerUnitID) && meta.OwnerUserID != rejectorID {
		m.logShare(req.DocID, rejectorID, ActionShareRejected, OutcomeDenied, "not manager or head")
		return nil, ErrAccessDenied
	}
	req.ApprovalStatus = ApprovalRejected
	req.Reason = reason
	m.logShare(req.DocID, rejectorID, ActionShareRejected, OutcomeSuccess,
		fmt.Sprintf("share=%s reason=%s", shareID, reason))
	return req, m.putShare(req)
}

// RevokeShare marks a share as revoked and removes the corresponding ACL grant.
func (m *ShareManager) RevokeShare(shareID, revokedBy string) (*ShareRequest, error) {
	req, err := m.GetShare(shareID)
	if err != nil {
		return nil, err
	}
	if req.Revoked {
		return nil, ErrRevoked
	}
	now := time.Now().UTC()
	req.Revoked = true
	req.RevokedBy = revokedBy
	req.RevokedAt = &now
	_ = m.removeGrant(req)

	m.logShare(req.DocID, revokedBy, ActionShareRevoked, OutcomeSuccess,
		fmt.Sprintf("share=%s grant_to=%s/%s", shareID, req.GrantToType, req.GrantToID))

	return req, m.putShare(req)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (m *ShareManager) logShare(docID, actor, action, outcome, detail string) {
	if m.audit == nil {
		return
	}
	m.audit.Log(DocAccessEvent{
		DocID:   docID,
		Actor:   actor,
		Action:  action,
		Outcome: outcome,
		Detail:  detail,
	})
}

func (m *ShareManager) applyGrant(req *ShareRequest) error {
	switch req.GrantToType {
	case GrantTypeUser:
		return m.docMgr.GrantUser(req.DocID, UserGrant{UserID: req.GrantToID, Permissions: req.Permissions})
	case GrantTypeUnit:
		return m.docMgr.GrantUnit(req.DocID, UnitGrant{UnitID: req.GrantToID, Permissions: req.Permissions})
	case GrantTypeDept:
		return m.docMgr.GrantUnit(req.DocID, UnitGrant{DeptID: req.GrantToID, Permissions: req.Permissions})
	case GrantTypeCompany:
		acl, err := m.docMgr.GetACL(req.DocID)
		if err != nil {
			return err
		}
		for i, g := range acl.InstitutionGrants {
			if g.CompanyID == req.GrantToID {
				acl.InstitutionGrants[i].Permissions = req.Permissions
				acl.UpdatedAt = time.Now().UTC()
				return m.docMgr.putACL(acl)
			}
		}
		acl.InstitutionGrants = append(acl.InstitutionGrants, InstitutionGrant{CompanyID: req.GrantToID, Permissions: req.Permissions})
		acl.UpdatedAt = time.Now().UTC()
		return m.docMgr.putACL(acl)
	}
	return nil
}

func (m *ShareManager) removeGrant(req *ShareRequest) error {
	acl, err := m.docMgr.GetACL(req.DocID)
	if err != nil {
		return err
	}
	switch req.GrantToType {
	case GrantTypeUser:
		filtered := acl.UserGrants[:0]
		for _, g := range acl.UserGrants {
			if g.UserID != req.GrantToID {
				filtered = append(filtered, g)
			}
		}
		acl.UserGrants = filtered
	case GrantTypeUnit:
		filtered := acl.UnitGrants[:0]
		for _, g := range acl.UnitGrants {
			if g.UnitID != req.GrantToID {
				filtered = append(filtered, g)
			}
		}
		acl.UnitGrants = filtered
	case GrantTypeDept:
		filtered := acl.UnitGrants[:0]
		for _, g := range acl.UnitGrants {
			if g.DeptID != req.GrantToID {
				filtered = append(filtered, g)
			}
		}
		acl.UnitGrants = filtered
	case GrantTypeCompany:
		filtered := acl.InstitutionGrants[:0]
		for _, g := range acl.InstitutionGrants {
			if g.CompanyID != req.GrantToID {
				filtered = append(filtered, g)
			}
		}
		acl.InstitutionGrants = filtered
	}
	acl.UpdatedAt = time.Now().UTC()
	return m.docMgr.putACL(acl)
}

func (m *ShareManager) putShare(req *ShareRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(shareReqPrefix+req.ShareID), b)
}

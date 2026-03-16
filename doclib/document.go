package doclib

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	docMetaPrefix = "doc:meta:"
	docACLPrefix  = "doc:acl:"
)

// ClassificationLevel represents a document sensitivity tier.
type ClassificationLevel string

const (
	ClassPublic       ClassificationLevel = "public"
	ClassInternal     ClassificationLevel = "internal"
	ClassConfidential ClassificationLevel = "confidential"
	ClassRestricted   ClassificationLevel = "restricted"
	ClassTopSecret    ClassificationLevel = "top_secret"
)

// DocumentStatus is the lifecycle state of a document.
type DocumentStatus string

const (
	StatusDraft       DocumentStatus = "draft"
	StatusUnderReview DocumentStatus = "under_review"
	StatusApproved    DocumentStatus = "approved"
	StatusPublished   DocumentStatus = "published"
	StatusArchived    DocumentStatus = "archived"
	StatusRejected    DocumentStatus = "rejected"
)

// DocumentMeta stores all metadata about a document (no binary content).
type DocumentMeta struct {
	DocID                 string              `json:"doc_id"`
	Title                 string              `json:"title"`
	Description           string              `json:"description"`
	DocType               string              `json:"doc_type"`
	ContentType           string              `json:"content_type"`
	OwnerUserID           string              `json:"owner_user_id"`
	OwnerUnitID           string              `json:"owner_unit_id"`
	OwnerDeptID           string              `json:"owner_dept_id"`
	OwnerCompanyID        string              `json:"owner_company_id"`
	ObjectPath            string              `json:"object_path"`
	ClassificationLevel   ClassificationLevel `json:"classification_level"`
	Tags                  []string            `json:"tags"`
	CustomMetadata        map[string]string   `json:"custom_metadata"`
	Status                DocumentStatus      `json:"status"`
	RequiresShareApproval bool                `json:"requires_share_approval"`
	CreatedAt             time.Time           `json:"created_at"`
	CreatedBy             string              `json:"created_by"`
	ModifiedAt            time.Time           `json:"modified_at"`
	ModifiedBy            string              `json:"modified_by"`
	Version               int                 `json:"version"`
	Checksum              string              `json:"checksum"`
}

// UnitGrant grants permissions to an entire unit (or dept-level if DeptID is set).
type UnitGrant struct {
	UnitID      string   `json:"unit_id"`
	DeptID      string   `json:"dept_id"`
	CompanyID   string   `json:"company_id"`
	Permissions []string `json:"permissions"`
}

// UserGrant grants permissions directly to a specific user.
type UserGrant struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

// InstitutionGrant grants permissions to a whole company.
type InstitutionGrant struct {
	CompanyID   string   `json:"company_id"`
	Permissions []string `json:"permissions"`
}

// DocumentACL is the access-control list for a document.
type DocumentACL struct {
	DocID             string             `json:"doc_id"`
	Owner             string             `json:"owner"`
	UnitGrants        []UnitGrant        `json:"unit_grants"`
	UserGrants        []UserGrant        `json:"user_grants"`
	InstitutionGrants []InstitutionGrant `json:"institution_grants"`
	PublicRead        bool               `json:"public_read"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

// DocManager handles document CRUD and access control.
type DocManager struct {
	db     *velocity.DB
	orgMgr *OrgManager
	audit  *AuditManager
}

// NewDocManager returns a DocManager.
func NewDocManager(db *velocity.DB, orgMgr *OrgManager, audit *AuditManager) *DocManager {
	return &DocManager{db: db, orgMgr: orgMgr, audit: audit}
}

// CreateDocument stores metadata and binary content via object storage.
func (m *DocManager) CreateDocument(meta *DocumentMeta, content io.Reader, size int64) (*DocumentMeta, error) {
	if strings.TrimSpace(meta.Title) == "" {
		return nil, fmt.Errorf("%w: title required", ErrInvalidInput)
	}
	meta.DocID = uuid.NewString()
	meta.CreatedAt = time.Now().UTC()
	meta.ModifiedAt = meta.CreatedAt
	meta.Status = StatusDraft
	meta.Version = 1

	if content != nil {
		objPath := fmt.Sprintf("doclib/%s/%s", meta.OwnerUnitID, meta.DocID)
		opts := &velocity.ObjectOptions{
			Version:      velocity.DefaultVersion,
			Encrypt:      true,
			StorageClass: "STANDARD",
		}
		objMeta, err := m.db.StoreObjectStream(objPath, meta.ContentType, meta.OwnerUserID, content, size, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to store content: %w", err)
		}
		meta.ObjectPath = objPath
		meta.Checksum = objMeta.Hash
	}

	if err := m.putMeta(meta); err != nil {
		return nil, err
	}

	acl := &DocumentACL{
		DocID:     meta.DocID,
		Owner:     meta.OwnerUserID,
		UpdatedAt: time.Now().UTC(),
	}
	if err := m.putACL(acl); err != nil {
		return nil, err
	}

	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:   meta.DocID,
			Actor:   meta.OwnerUserID,
			Action:  ActionDocCreated,
			Outcome: OutcomeSuccess,
			Detail:  fmt.Sprintf("title=%q classification=%s", meta.Title, meta.ClassificationLevel),
			Metadata: map[string]string{
				"unit_id":    meta.OwnerUnitID,
				"doc_type":   meta.DocType,
				"has_binary": fmt.Sprintf("%v", content != nil),
			},
		})
	}
	return meta, nil
}

// GetDocument retrieves document metadata.
func (m *DocManager) GetDocument(docID string) (*DocumentMeta, error) {
	b, err := m.db.Get([]byte(docMetaPrefix + docID))
	if err != nil {
		return nil, ErrNotFound
	}
	var meta DocumentMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// UpdateDocument updates document metadata fields and emits an audit event.
func (m *DocManager) UpdateDocument(docID, modifiedBy string, update func(*DocumentMeta)) (*DocumentMeta, error) {
	meta, err := m.GetDocument(docID)
	if err != nil {
		return nil, err
	}
	before := meta.Status
	update(meta)
	meta.ModifiedAt = time.Now().UTC()
	meta.ModifiedBy = modifiedBy
	meta.Version++
	if err := m.putMeta(meta); err != nil {
		return nil, err
	}
	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:   docID,
			Actor:   modifiedBy,
			Action:  ActionDocUpdated,
			Outcome: OutcomeSuccess,
			Detail:  fmt.Sprintf("v%d status=%s→%s", meta.Version, before, meta.Status),
		})
	}
	return meta, nil
}

// DeleteDocument removes document metadata, ACL, and binary content.
func (m *DocManager) DeleteDocument(docID, userID string) error {
	meta, err := m.GetDocument(docID)
	if err != nil {
		return err
	}
	if !m.CanAccess(userID, docID, "delete") {
		if m.audit != nil {
			m.audit.Log(DocAccessEvent{
				DocID:   docID,
				Actor:   userID,
				Action:  ActionDocDeleted,
				Outcome: OutcomeDenied,
				Detail:  "lacks delete permission",
			})
		}
		return ErrAccessDenied
	}
	if meta.ObjectPath != "" {
		_ = m.db.DeleteObject(meta.ObjectPath, userID)
	}
	_ = m.db.Delete([]byte(docMetaPrefix + docID))
	_ = m.db.Delete([]byte(docACLPrefix + docID))

	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:   docID,
			Actor:   userID,
			Action:  ActionDocDeleted,
			Outcome: OutcomeSuccess,
		})
	}
	return nil
}

// GetContent retrieves the binary content of a document with full audit trail.
func (m *DocManager) GetContent(docID, userID string) ([]byte, *DocumentMeta, error) {
	return m.GetContentWithContext(docID, userID, "", "")
}

// GetContentWithContext retrieves binary content and logs IP/session to the access chain.
func (m *DocManager) GetContentWithContext(docID, userID, ip, sessionID string) ([]byte, *DocumentMeta, error) {
	meta, err := m.GetDocument(docID)
	if err != nil {
		return nil, nil, err
	}
	if !m.CanAccess(userID, docID, "read") {
		if m.audit != nil {
			m.audit.Log(DocAccessEvent{
				DocID:     docID,
				Actor:     userID,
				Action:    ActionDocAccessDenied,
				Outcome:   OutcomeDenied,
				IPAddress: ip,
				SessionID: sessionID,
				Detail:    "content access denied",
			})
		}
		return nil, nil, ErrAccessDenied
	}
	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:     docID,
			Actor:     userID,
			Action:    ActionDocContentAccessed,
			Outcome:   OutcomeSuccess,
			IPAddress: ip,
			SessionID: sessionID,
			Detail:    fmt.Sprintf("classification=%s version=%d", meta.ClassificationLevel, meta.Version),
			Metadata: map[string]string{
				"checksum": meta.Checksum,
			},
		})
	}
	if meta.ObjectPath == "" {
		return nil, meta, nil
	}
	data, _, err := m.db.GetObject(meta.ObjectPath, userID)
	if err != nil {
		return nil, nil, err
	}
	return data, meta, nil
}

// ReadDocument logs a doc.read event (metadata-only access, e.g. GET /documents/:id).
func (m *DocManager) ReadDocument(docID, userID, ip string) (*DocumentMeta, error) {
	meta, err := m.GetDocument(docID)
	if err != nil {
		return nil, err
	}
	if !m.CanAccess(userID, docID, "read") {
		if m.audit != nil {
			m.audit.Log(DocAccessEvent{
				DocID:     docID,
				Actor:     userID,
				Action:    ActionDocAccessDenied,
				Outcome:   OutcomeDenied,
				IPAddress: ip,
			})
		}
		return nil, ErrAccessDenied
	}
	if m.audit != nil {
		m.audit.Log(DocAccessEvent{
			DocID:     docID,
			Actor:     userID,
			Action:    ActionDocRead,
			Outcome:   OutcomeSuccess,
			IPAddress: ip,
			Detail:    fmt.Sprintf("status=%s v%d", meta.Status, meta.Version),
		})
	}
	return meta, nil
}

// GetACL retrieves the ACL for a document.
func (m *DocManager) GetACL(docID string) (*DocumentACL, error) {
	b, err := m.db.Get([]byte(docACLPrefix + docID))
	if err != nil {
		return nil, ErrNotFound
	}
	var acl DocumentACL
	if err := json.Unmarshal(b, &acl); err != nil {
		return nil, err
	}
	return &acl, nil
}

// GrantUnit adds a unit grant to the document ACL.
func (m *DocManager) GrantUnit(docID string, grant UnitGrant) error {
	acl, err := m.GetACL(docID)
	if err != nil {
		return err
	}
	for i, g := range acl.UnitGrants {
		if g.UnitID == grant.UnitID && g.DeptID == grant.DeptID {
			acl.UnitGrants[i].Permissions = grant.Permissions
			acl.UpdatedAt = time.Now().UTC()
			return m.putACL(acl)
		}
	}
	acl.UnitGrants = append(acl.UnitGrants, grant)
	acl.UpdatedAt = time.Now().UTC()
	return m.putACL(acl)
}

// GrantUser adds a user grant to the document ACL.
func (m *DocManager) GrantUser(docID string, grant UserGrant) error {
	acl, err := m.GetACL(docID)
	if err != nil {
		return err
	}
	for i, g := range acl.UserGrants {
		if g.UserID == grant.UserID {
			acl.UserGrants[i].Permissions = grant.Permissions
			acl.UpdatedAt = time.Now().UTC()
			return m.putACL(acl)
		}
	}
	acl.UserGrants = append(acl.UserGrants, grant)
	acl.UpdatedAt = time.Now().UTC()
	return m.putACL(acl)
}

// CanAccess checks whether userID may perform action on docID.
func (m *DocManager) CanAccess(userID, docID, action string) bool {
	meta, err := m.GetDocument(docID)
	if err != nil {
		return false
	}
	if meta.OwnerUserID == userID {
		return true
	}
	acl, err := m.GetACL(docID)
	if err != nil {
		return false
	}
	if acl.PublicRead && action == "read" {
		return true
	}
	for _, g := range acl.UserGrants {
		if g.UserID == userID && hasPermission(g.Permissions, action) {
			return true
		}
	}
	mems, err := m.orgMgr.GetMemberships(userID)
	if err == nil {
		for _, mem := range mems {
			for _, ig := range acl.InstitutionGrants {
				if ig.CompanyID == mem.CompanyID && hasPermission(ig.Permissions, action) {
					return true
				}
			}
			for _, ug := range acl.UnitGrants {
				if ug.UnitID == mem.UnitID && hasPermission(ug.Permissions, action) {
					return true
				}
				if ug.DeptID != "" && ug.DeptID == mem.DeptID && hasPermission(ug.Permissions, action) {
					return true
				}
			}
		}
	}
	return false
}

// hasPermission checks whether the permission list grants the requested action.
func hasPermission(perms []string, action string) bool {
	for _, p := range perms {
		if p == action || p == "full" || p == "manage" {
			return true
		}
		if action == "read" && (p == "write" || p == "approve" || p == "publish") {
			return true
		}
	}
	return false
}

func (m *DocManager) putMeta(meta *DocumentMeta) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(docMetaPrefix+meta.DocID), b)
}

func (m *DocManager) putACL(acl *DocumentACL) error {
	b, err := json.Marshal(acl)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(docACLPrefix+acl.DocID), b)
}

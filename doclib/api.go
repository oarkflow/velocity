package doclib

import (
	"context"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
)

// Manager composes all doclib sub-managers.
type Manager struct {
	Org       *OrgManager
	Doc       *DocManager
	Share     *ShareManager
	Lifecycle *LifecycleManager
	Audit     *AuditManager
	Dispatch  *DispatchManager
	Comment   *CommentManager
}

// NewManager creates a fully-wired Manager.
func NewManager(db *velocity.DB) *Manager {
	org := NewOrgManager(db)
	audit := NewAuditManager(db)
	doc := NewDocManager(db, org, audit)
	share := NewShareManager(db, doc, org, audit)
	lc := NewLifecycleManager(db, doc, audit)
	dispatch := NewDispatchManager(db, doc, audit)
	comment := NewCommentManager(db, doc)
	return &Manager{
		Org:       org,
		Doc:       doc,
		Share:     share,
		Lifecycle: lc,
		Audit:     audit,
		Dispatch:  dispatch,
		Comment:   comment,
	}
}

// RegisterRoutes mounts all /api/doclib routes on the existing fiber app.
// jwtMiddleware should be s.jwtAuthMiddleware() from the HTTPServer.
func RegisterRoutes(app *fiber.App, mgr *Manager, jwtMiddleware fiber.Handler) {
	g := app.Group("/api/doclib", jwtMiddleware)

	// ---- Org hierarchy ----
	g.Post("/orgs", mgr.handleCreateCompany)
	g.Get("/orgs", mgr.handleListCompanies)
	g.Get("/orgs/:companyID", mgr.handleGetCompany)
	g.Post("/orgs/:companyID/depts", mgr.handleCreateDept)
	g.Get("/orgs/:companyID/depts", mgr.handleListDepts)
	g.Get("/depts/:deptID", mgr.handleGetDept)
	g.Post("/depts/:deptID/units", mgr.handleCreateUnit)
	g.Get("/depts/:deptID/units", mgr.handleListUnits)
	g.Get("/units/:unitID", mgr.handleGetUnit)
	g.Post("/units/:unitID/members", mgr.handleAddMember)
	g.Get("/units/:unitID/members", mgr.handleListUnitMembers)
	g.Delete("/units/:unitID/members/:uid", mgr.handleRemoveMember)
	g.Get("/users/:userID/memberships", mgr.handleGetUserMemberships)
	g.Get("/users/:userID/documents", mgr.handleGetUserDocuments)
	g.Get("/users", mgr.handleListUsers)

	// ---- Documents ----
	g.Post("/documents", mgr.handleCreateDocument)
	g.Get("/documents", mgr.handleQueryDocuments)
	g.Get("/documents/:docID", mgr.handleGetDocument)
	g.Get("/documents/:docID/content", mgr.handleGetContent)
	g.Put("/documents/:docID", mgr.handleUpdateDocument)
	g.Delete("/documents/:docID", mgr.handleDeleteDocument)
	g.Get("/documents/:docID/related", mgr.handleGetRelated)
	g.Post("/documents/:docID/comments", mgr.handleAddComment)
	g.Get("/documents/:docID/comments", mgr.handleListComments)

	// ---- Dashboard ----
	g.Get("/dashboard/stats", mgr.handleDashboardStats)

	// ---- Lifecycle ----
	g.Put("/documents/:docID/status", mgr.handleTransitionStatus)
	g.Get("/documents/:docID/history", mgr.handleGetHistory)

	// ---- Shares ----
	g.Post("/documents/:docID/shares", mgr.handleCreateShare)
	g.Get("/documents/:docID/shares", mgr.handleListShares)
	g.Post("/shares/:shareID/approve", mgr.handleApproveShare)
	g.Post("/shares/:shareID/reject", mgr.handleRejectShare)
	g.Delete("/shares/:shareID", mgr.handleRevokeShare)

	// ---- Audit / Access chain ----
	g.Get("/documents/:docID/access-chain", mgr.handleGetAccessChain)
	g.Get("/documents/:docID/access-chain/summary", mgr.handleGetAccessChainSummary)

	// ---- Dispatch (envelopes to banks / governments / services) ----
	g.Post("/documents/:docID/dispatch", mgr.handleSendDispatch)
	g.Get("/documents/:docID/dispatches", mgr.handleListDispatches)
	g.Post("/dispatches/:dispatchID/acknowledge", mgr.handleAcknowledgeDispatch)
	g.Post("/dispatches/:dispatchID/recall", mgr.handleRecallDispatch)
	g.Get("/dispatches/:dispatchID/envelope", mgr.handleGetEnvelope)
	g.Get("/dispatches/:dispatchID", mgr.handleGetDispatch)
}

// actorFromCtx extracts the authenticated username set by jwtAuthMiddleware.
func actorFromCtx(c fiber.Ctx) string {
	if u, ok := c.Locals("username").(string); ok {
		return u
	}
	return ""
}

// ============================================================
// Org handlers
// ============================================================

func (m *Manager) handleCreateCompany(c fiber.Ctx) error {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	company, err := m.Org.CreateCompany(req.Name, req.Description, actorFromCtx(c))
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(company)
}

func (m *Manager) handleListCompanies(c fiber.Ctx) error {
	companies, err := m.Org.ListCompanies()
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"companies": companies, "total": len(companies)})
}

func (m *Manager) handleCreateDept(c fiber.Ctx) error {
	companyID := c.Params("companyID")
	var req struct {
		Name       string `json:"name"`
		Code       string `json:"code"`
		HeadUserID string `json:"head_user_id"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	dept, err := m.Org.CreateDepartment(companyID, req.Name, req.Code, req.HeadUserID, actorFromCtx(c))
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(dept)
}

func (m *Manager) handleListDepts(c fiber.Ctx) error {
	companyID := c.Params("companyID")
	depts, err := m.Org.ListDepartments(companyID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"departments": depts, "total": len(depts)})
}

func (m *Manager) handleCreateUnit(c fiber.Ctx) error {
	deptID := c.Params("deptID")
	var req struct {
		CompanyID     string `json:"company_id"`
		Name          string `json:"name"`
		Code          string `json:"code"`
		ManagerUserID string `json:"manager_user_id"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	unit, err := m.Org.CreateUnit(deptID, req.CompanyID, req.Name, req.Code, req.ManagerUserID)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(unit)
}

func (m *Manager) handleListUnits(c fiber.Ctx) error {
	deptID := c.Params("deptID")
	units, err := m.Org.ListUnits(deptID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"units": units, "total": len(units)})
}

func (m *Manager) handleAddMember(c fiber.Ctx) error {
	unitID := c.Params("unitID")
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	mem, err := m.Org.AddMember(req.UserID, unitID, req.Role)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(mem)
}

func (m *Manager) handleRemoveMember(c fiber.Ctx) error {
	unitID := c.Params("unitID")
	uid := c.Params("uid")
	if err := m.Org.RemoveMember(uid, unitID); err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"status": "removed"})
}

// ============================================================
// Document handlers
// ============================================================

func (m *Manager) handleCreateDocument(c fiber.Ctx) error {
	actor := actorFromCtx(c)

	meta := &DocumentMeta{
		CreatedBy:   actor,
		OwnerUserID: actor,
	}

	if err := bindDocMeta(c, meta); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	var (
		content interface{ Read([]byte) (int, error) }
		size    = int64(-1)
	)

	if fh, err := c.FormFile("file"); err == nil {
		f, err := fh.Open()
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "cannot open file")
		}
		defer f.Close()
		content = f
		size = fh.Size
		if meta.ContentType == "" {
			meta.ContentType = fh.Header.Get("Content-Type")
		}
	}

	created, err := m.Doc.CreateDocument(meta, content, size)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (m *Manager) handleQueryDocuments(c fiber.Ctx) error {
	actor := actorFromCtx(c)
	f := DocumentFilter{
		RequesterID:         actor,
		UnitID:              c.Query("unit_id"),
		DeptID:              c.Query("dept_id"),
		CompanyID:           c.Query("company_id"),
		Status:              DocumentStatus(c.Query("status")),
		ClassificationLevel: ClassificationLevel(c.Query("classification")),
		DocType:             c.Query("doc_type"),
		OwnerUserID:         c.Query("owner_user_id"),
		FullText:            c.Query("q"),
		Limit:               fiber.Query[int](c, "limit", 50),
		Offset:              fiber.Query[int](c, "offset", 0),
		SortBy:              c.Query("sort_by"),
	}
	if tags := c.Query("tags"); tags != "" {
		f.Tags = strings.Split(tags, ",")
	}
	docs, err := m.Doc.QueryDocuments(f)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"documents": docs, "total": len(docs)})
}

func (m *Manager) handleGetDocument(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	ip := c.IP()
	meta, err := m.Doc.ReadDocument(docID, actor, ip)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(meta)
}

func (m *Manager) handleGetContent(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	ip := c.IP()
	sessionID, _ := c.Locals("session_id").(string)
	data, meta, err := m.Doc.GetContentWithContext(docID, actor, ip, sessionID)
	if err != nil {
		return fiberErr(err)
	}
	if data == nil {
		return fiber.NewError(fiber.StatusNoContent, "no content stored")
	}
	ct := meta.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	c.Set(fiber.HeaderContentType, ct)
	c.Set("Content-Disposition", `attachment; filename="`+meta.Title+`"`)
	return c.Send(data)
}

func (m *Manager) handleUpdateDocument(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "write") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	var patch map[string]interface{}
	if err := c.Bind().Body(&patch); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	meta, err := m.Doc.UpdateDocument(docID, actor, func(d *DocumentMeta) {
		if v, ok := patch["title"].(string); ok {
			d.Title = v
		}
		if v, ok := patch["description"].(string); ok {
			d.Description = v
		}
		if v, ok := patch["doc_type"].(string); ok {
			d.DocType = v
		}
		if v, ok := patch["classification_level"].(string); ok {
			d.ClassificationLevel = ClassificationLevel(v)
		}
		if v, ok := patch["requires_share_approval"].(bool); ok {
			d.RequiresShareApproval = v
		}
	})
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(meta)
}

func (m *Manager) handleDeleteDocument(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if err := m.Doc.DeleteDocument(docID, actor); err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"status": "deleted"})
}

// ============================================================
// Lifecycle handlers
// ============================================================

func (m *Manager) handleTransitionStatus(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	var req struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	meta, err := m.Lifecycle.Transition(docID, actor, c.IP(), req.Comment, DocumentStatus(req.Status))
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(meta)
}

func (m *Manager) handleGetHistory(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	history, err := m.Lifecycle.GetHistory(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"history": history, "total": len(history)})
}

// ============================================================
// Share handlers
// ============================================================

func (m *Manager) handleCreateShare(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	var req struct {
		GrantToType string     `json:"grant_to_type"`
		GrantToID   string     `json:"grant_to_id"`
		Permissions []string   `json:"permissions"`
		Reason      string     `json:"reason"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	share, err := m.Share.CreateShare(docID, actor, GrantType(req.GrantToType), req.GrantToID, req.Permissions, req.Reason, req.ExpiresAt)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(share)
}

func (m *Manager) handleListShares(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	shares, err := m.Share.ListShares(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"shares": shares, "total": len(shares)})
}

func (m *Manager) handleApproveShare(c fiber.Ctx) error {
	shareID := c.Params("shareID")
	actor := actorFromCtx(c)
	share, err := m.Share.ApproveShare(shareID, actor)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(share)
}

func (m *Manager) handleRejectShare(c fiber.Ctx) error {
	shareID := c.Params("shareID")
	actor := actorFromCtx(c)
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.Bind().Body(&req)
	share, err := m.Share.RejectShare(shareID, actor, req.Reason)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(share)
}

func (m *Manager) handleRevokeShare(c fiber.Ctx) error {
	shareID := c.Params("shareID")
	actor := actorFromCtx(c)
	share, err := m.Share.RevokeShare(shareID, actor)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(share)
}

// ============================================================
// Audit / Access chain handlers
// ============================================================

// handleGetAccessChain returns the full hash-linked access chain for a document.
// The actor must have read access to the document.
func (m *Manager) handleGetAccessChain(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	chain, err := m.Audit.GetChain(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"doc_id": docID, "chain": chain, "total": len(chain)})
}

// handleGetAccessChainSummary returns aggregate stats and chain integrity status.
func (m *Manager) handleGetAccessChainSummary(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	summary, err := m.Audit.GetChainSummary(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(summary)
}

// ============================================================
// Dispatch handlers
// ============================================================

// handleSendDispatch seals a document into a Velocity envelope and dispatches it.
func (m *Manager) handleSendDispatch(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	ip := c.IP()

	var body struct {
		Recipients []DispatchRecipient `json:"recipients"`
		Purpose    string              `json:"purpose"`
		CaseRef    string              `json:"case_ref"`
		ExpiresAt  *time.Time          `json:"expires_at"`
		TimeLock   bool                `json:"time_lock"`
		LegalNote  string              `json:"legal_note"`
		Tags       map[string]string   `json:"tags"`
	}
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}

	req := DispatchRequest{
		DocID:      docID,
		SentBy:     actor,
		Recipients: body.Recipients,
		Purpose:    body.Purpose,
		CaseRef:    body.CaseRef,
		ExpiresAt:  body.ExpiresAt,
		TimeLock:   body.TimeLock,
		LegalNote:  body.LegalNote,
		Tags:       body.Tags,
	}

	dispatch, err := m.Dispatch.SendDispatch(context.Background(), req, ip)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(dispatch)
}

// handleListDispatches lists all dispatch records for a document.
func (m *Manager) handleListDispatches(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	dispatches, err := m.Dispatch.ListDispatches(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"dispatches": dispatches, "total": len(dispatches)})
}

// handleGetDispatch retrieves a single dispatch record.
func (m *Manager) handleGetDispatch(c fiber.Ctx) error {
	dispatchID := c.Params("dispatchID")
	actor := actorFromCtx(c)
	d, err := m.Dispatch.GetDispatch(dispatchID)
	if err != nil {
		return fiberErr(err)
	}
	// Gate on read access to the originating document.
	if !m.Doc.CanAccess(actor, d.DocID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	return c.JSON(d)
}

// handleAcknowledgeDispatch marks a dispatch as acknowledged by the receiving actor.
func (m *Manager) handleAcknowledgeDispatch(c fiber.Ctx) error {
	dispatchID := c.Params("dispatchID")
	actor := actorFromCtx(c)
	ip := c.IP()
	d, err := m.Dispatch.AcknowledgeDispatch(context.Background(), dispatchID, actor, ip)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(d)
}

// handleRecallDispatch marks a dispatch as recalled and appends a custody event.
func (m *Manager) handleRecallDispatch(c fiber.Ctx) error {
	dispatchID := c.Params("dispatchID")
	actor := actorFromCtx(c)
	ip := c.IP()
	var req struct {
		Note string `json:"note"`
	}
	_ = c.Bind().Body(&req)
	d, err := m.Dispatch.RecallDispatch(context.Background(), dispatchID, actor, req.Note, ip)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(d)
}

// handleGetEnvelope returns the full Velocity envelope (with custody chain) for a dispatch.
// Only actors with read access on the originating document may retrieve this.
func (m *Manager) handleGetEnvelope(c fiber.Ctx) error {
	dispatchID := c.Params("dispatchID")
	actor := actorFromCtx(c)
	envelope, err := m.Dispatch.GetEnvelope(context.Background(), dispatchID, actor)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(envelope)
}

// ============================================================
// New org detail handlers
// ============================================================

func (m *Manager) handleGetCompany(c fiber.Ctx) error {
	companyID := c.Params("companyID")
	company, err := m.Org.GetCompany(companyID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(company)
}

func (m *Manager) handleGetDept(c fiber.Ctx) error {
	deptID := c.Params("deptID")
	dept, err := m.Org.GetDepartment(deptID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(dept)
}

func (m *Manager) handleGetUnit(c fiber.Ctx) error {
	unitID := c.Params("unitID")
	unit, err := m.Org.GetUnit(unitID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(unit)
}

func (m *Manager) handleListUnitMembers(c fiber.Ctx) error {
	unitID := c.Params("unitID")
	members, err := m.Org.ListUnitMembers(unitID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"members": members, "total": len(members)})
}

func (m *Manager) handleGetUserMemberships(c fiber.Ctx) error {
	userID := c.Params("userID")
	memberships, err := m.Org.GetMemberships(userID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"memberships": memberships, "total": len(memberships)})
}

func (m *Manager) handleGetUserDocuments(c fiber.Ctx) error {
	userID := c.Params("userID")
	actor := actorFromCtx(c)
	f := DocumentFilter{
		RequesterID: actor,
		OwnerUserID: userID,
		Limit:       fiber.Query[int](c, "limit", 50),
		Offset:      fiber.Query[int](c, "offset", 0),
	}
	docs, err := m.Doc.QueryDocuments(f)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"documents": docs, "total": len(docs)})
}

func (m *Manager) handleListUsers(c fiber.Ctx) error {
	users, err := m.Org.ListAllUsers()
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"users": users, "total": len(users)})
}

// ============================================================
// Related documents handler
// ============================================================

func (m *Manager) handleGetRelated(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	limit := fiber.Query[int](c, "limit", 10)
	related, err := m.Doc.FindRelated(docID, actor, limit)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"documents": related, "total": len(related)})
}

// ============================================================
// Comment handlers
// ============================================================

func (m *Manager) handleAddComment(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
	}
	comment, err := m.Comment.AddComment(docID, actor, req.Content)
	if err != nil {
		return fiberErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(comment)
}

func (m *Manager) handleListComments(c fiber.Ctx) error {
	docID := c.Params("docID")
	actor := actorFromCtx(c)
	if !m.Doc.CanAccess(actor, docID, "read") {
		return fiber.NewError(fiber.StatusForbidden, "access denied")
	}
	comments, err := m.Comment.ListComments(docID)
	if err != nil {
		return fiberErr(err)
	}
	return c.JSON(fiber.Map{"comments": comments, "total": len(comments)})
}

// ============================================================
// Dashboard stats handler
// ============================================================

func (m *Manager) handleDashboardStats(c fiber.Ctx) error {
	actor := actorFromCtx(c)
	f := DocumentFilter{RequesterID: actor, Limit: 1000}
	docs, err := m.Doc.QueryDocuments(f)
	if err != nil {
		return fiberErr(err)
	}

	byStatus := make(map[string]int)
	byClassification := make(map[string]int)
	var recent []*DocumentMeta
	for _, d := range docs {
		byStatus[string(d.Status)]++
		byClassification[string(d.ClassificationLevel)]++
	}

	// Recent docs: last 10 by created_at (docs are unsorted, so find top 10)
	if len(docs) > 0 {
		// Copy and sort by created_at desc
		sorted := make([]*DocumentMeta, len(docs))
		copy(sorted, docs)
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j].CreatedAt.After(sorted[i].CreatedAt) {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
		limit := 10
		if len(sorted) < limit {
			limit = len(sorted)
		}
		recent = sorted[:limit]
	}

	return c.JSON(fiber.Map{
		"total_documents":     len(docs),
		"by_status":           byStatus,
		"by_classification":   byClassification,
		"recent_documents":    recent,
	})
}

// ============================================================
// Helpers
// ============================================================

// fiberErr maps domain errors to HTTP status codes.
func fiberErr(err error) error {
	switch err {
	case ErrNotFound:
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case ErrAccessDenied:
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case ErrAlreadyExists:
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case ErrInvalidInput:
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case ErrRevoked, ErrNotPending, ErrAlreadyApproved:
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// bindDocMeta parses document metadata from a JSON body or form fields.
func bindDocMeta(c fiber.Ctx, meta *DocumentMeta) error {
	ct := c.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		return c.Bind().Body(meta)
	}
	meta.Title = c.FormValue("title")
	meta.Description = c.FormValue("description")
	meta.DocType = c.FormValue("doc_type")
	meta.OwnerUnitID = c.FormValue("owner_unit_id")
	meta.OwnerDeptID = c.FormValue("owner_dept_id")
	meta.OwnerCompanyID = c.FormValue("owner_company_id")
	meta.ClassificationLevel = ClassificationLevel(c.FormValue("classification_level"))
	if tagStr := c.FormValue("tags"); tagStr != "" {
		meta.Tags = strings.Split(tagStr, ",")
	}
	return nil
}

package doclib_test

import (
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/doclib"
)

// openTestDB opens a temporary Velocity DB for testing.
func openTestDB(t *testing.T) *velocity.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "doclib-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := velocity.New(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---- Org tests ----

func TestOrgCRUD(t *testing.T) {
	mgr := doclib.NewManager(openTestDB(t))

	company, err := mgr.Org.CreateCompany("Acme Corp", "big company", "sysop")
	if err != nil {
		t.Fatalf("create company: %v", err)
	}
	if company.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	got, err := mgr.Org.GetCompany(company.ID)
	if err != nil {
		t.Fatalf("get company: %v", err)
	}
	if got.Name != "Acme Corp" {
		t.Fatalf("expected Acme Corp, got %s", got.Name)
	}

	dept, err := mgr.Org.CreateDepartment(company.ID, "Engineering", "ENG", "manager1", "sysop")
	if err != nil {
		t.Fatalf("create dept: %v", err)
	}

	unit, err := mgr.Org.CreateUnit(dept.ID, company.ID, "Platform", "PLT", "manager1")
	if err != nil {
		t.Fatalf("create unit: %v", err)
	}

	mem, err := mgr.Org.AddMember("alice", unit.ID, "member")
	if err != nil {
		t.Fatalf("add member: %v", err)
	}
	if mem.UnitID != unit.ID {
		t.Fatalf("expected unitID %s, got %s", unit.ID, mem.UnitID)
	}
	if mem.DeptID != dept.ID {
		t.Fatalf("expected deptID %s, got %s", dept.ID, mem.DeptID)
	}

	// Remove member.
	if err := mgr.Org.RemoveMember("alice", unit.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	mems, _ := mgr.Org.GetMemberships("alice")
	if len(mems) != 0 {
		t.Fatalf("expected 0 active memberships after removal, got %d", len(mems))
	}
}

// ---- Access-control tests ----

func TestCanAccess(t *testing.T) {
	db := openTestDB(t)
	mgr := doclib.NewManager(db)

	// Setup org.
	company, _ := mgr.Org.CreateCompany("Co", "", "root")
	dept, _ := mgr.Org.CreateDepartment(company.ID, "D", "D", "manager1", "root")
	unit, _ := mgr.Org.CreateUnit(dept.ID, company.ID, "U", "U", "manager1")
	_, _ = mgr.Org.AddMember("alice", unit.ID, "member")
	// bob is NOT in the unit.

	meta := &doclib.DocumentMeta{
		Title:               "Test Doc",
		OwnerUserID:         "alice",
		OwnerUnitID:         unit.ID,
		OwnerDeptID:         dept.ID,
		OwnerCompanyID:      company.ID,
		ClassificationLevel: doclib.ClassInternal,
	}
	created, err := mgr.Doc.CreateDocument(meta, nil, -1)
	if err != nil {
		t.Fatalf("create doc: %v", err)
	}

	// Owner always has access.
	if !mgr.Doc.CanAccess("alice", created.DocID, "read") {
		t.Fatal("owner should have read access")
	}
	if !mgr.Doc.CanAccess("alice", created.DocID, "delete") {
		t.Fatal("owner should have delete access")
	}

	// bob has no access yet.
	if mgr.Doc.CanAccess("bob", created.DocID, "read") {
		t.Fatal("bob should not have read access yet")
	}

	// Grant bob unit-level read (alice's unit).
	_, _ = mgr.Org.AddMember("bob", unit.ID, "member")
	_ = mgr.Doc.GrantUnit(created.DocID, doclib.UnitGrant{UnitID: unit.ID, Permissions: []string{"read"}})

	if !mgr.Doc.CanAccess("bob", created.DocID, "read") {
		t.Fatal("bob should have read access after unit grant")
	}
	if mgr.Doc.CanAccess("bob", created.DocID, "write") {
		t.Fatal("bob should not have write access")
	}
}

// ---- Share approval flow ----

func TestShareApprovalFlow(t *testing.T) {
	db := openTestDB(t)
	mgr := doclib.NewManager(db)

	company, _ := mgr.Org.CreateCompany("Co", "", "root")
	dept, _ := mgr.Org.CreateDepartment(company.ID, "D", "D", "manager1", "root")
	unit1, _ := mgr.Org.CreateUnit(dept.ID, company.ID, "Unit1", "U1", "manager1")
	unit2, _ := mgr.Org.CreateUnit(dept.ID, company.ID, "Unit2", "U2", "manager2")
	_, _ = mgr.Org.AddMember("alice", unit1.ID, "member")
	_, _ = mgr.Org.AddMember("bob", unit2.ID, "member") //nolint:errcheck

	meta := &doclib.DocumentMeta{
		Title:                "Confidential Doc",
		OwnerUserID:          "alice",
		OwnerUnitID:          unit1.ID,
		OwnerDeptID:          dept.ID,
		OwnerCompanyID:       company.ID,
		ClassificationLevel:  doclib.ClassConfidential,
		RequiresShareApproval: true,
	}
	doc, err := mgr.Doc.CreateDocument(meta, nil, -1)
	if err != nil {
		t.Fatalf("create doc: %v", err)
	}

	// Bob cannot read yet.
	if mgr.Doc.CanAccess("bob", doc.DocID, "read") {
		t.Fatal("bob should not have access before share")
	}

	// Alice creates a share request for unit2.
	share, err := mgr.Share.CreateShare(doc.DocID, "alice", doclib.GrantTypeUnit, unit2.ID, []string{"read"}, "collab", nil)
	if err != nil {
		t.Fatalf("create share: %v", err)
	}
	if share.ApprovalStatus != doclib.ApprovalPending {
		t.Fatalf("expected pending, got %s", share.ApprovalStatus)
	}

	// Bob still cannot read (not yet approved).
	if mgr.Doc.CanAccess("bob", doc.DocID, "read") {
		t.Fatal("bob should not have access while share is pending")
	}

	// manager1 (unit manager) approves.
	approved, err := mgr.Share.ApproveShare(share.ShareID, "manager1")
	if err != nil {
		t.Fatalf("approve share: %v", err)
	}
	if approved.ApprovalStatus != doclib.ApprovalApproved {
		t.Fatalf("expected approved, got %s", approved.ApprovalStatus)
	}

	// Now bob can read.
	if !mgr.Doc.CanAccess("bob", doc.DocID, "read") {
		t.Fatal("bob should have read access after approval")
	}

	// Revoke share.
	_, err = mgr.Share.RevokeShare(share.ShareID, "alice")
	if err != nil {
		t.Fatalf("revoke share: %v", err)
	}
	// bob still has the unit grant (revoke removes it).
	if mgr.Doc.CanAccess("bob", doc.DocID, "read") {
		t.Fatal("bob should not have access after revocation")
	}
}

// ---- Lifecycle tests ----

func TestLifecycleTransitions(t *testing.T) {
	db := openTestDB(t)
	mgr := doclib.NewManager(db)

	company, _ := mgr.Org.CreateCompany("Co", "", "root")
	dept, _ := mgr.Org.CreateDepartment(company.ID, "D", "D", "manager1", "root")
	unit, _ := mgr.Org.CreateUnit(dept.ID, company.ID, "U", "U", "manager1")
	_, _ = mgr.Org.AddMember("alice", unit.ID, "member")

	meta := &doclib.DocumentMeta{
		Title:       "Lifecycle Doc",
		OwnerUserID: "alice",
		OwnerUnitID: unit.ID,
	}
	doc, err := mgr.Doc.CreateDocument(meta, nil, -1)
	if err != nil {
		t.Fatalf("create doc: %v", err)
	}

	steps := []doclib.DocumentStatus{
		doclib.StatusUnderReview,
		doclib.StatusApproved,
		doclib.StatusPublished,
		doclib.StatusArchived,
	}

	for _, s := range steps {
		doc, err = mgr.Lifecycle.Transition(doc.DocID, "alice", "127.0.0.1", "step", s)
		if err != nil {
			t.Fatalf("transition to %s: %v", s, err)
		}
		if doc.Status != s {
			t.Fatalf("expected status %s, got %s", s, doc.Status)
		}
	}

	history, err := mgr.Lifecycle.GetHistory(doc.DocID)
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if len(history) != len(steps) {
		t.Fatalf("expected %d history entries, got %d", len(steps), len(history))
	}
}

// ---- Query tests ----

func TestQueryDocuments(t *testing.T) {
	db := openTestDB(t)
	mgr := doclib.NewManager(db)

	company, _ := mgr.Org.CreateCompany("Co", "", "root")
	dept, _ := mgr.Org.CreateDepartment(company.ID, "D", "D", "manager1", "root")
	unit, _ := mgr.Org.CreateUnit(dept.ID, company.ID, "U", "U", "manager1")
	_, _ = mgr.Org.AddMember("alice", unit.ID, "member")

	for i, title := range []string{"Alpha Report", "Beta Analysis", "Gamma Summary"} {
		m := &doclib.DocumentMeta{
			Title:               title,
			OwnerUserID:         "alice",
			OwnerUnitID:         unit.ID,
			OwnerDeptID:         dept.ID,
			OwnerCompanyID:      company.ID,
			ClassificationLevel: doclib.ClassInternal,
			Tags:                []string{"tag-" + string(rune('a'+i))},
		}
		if _, err := mgr.Doc.CreateDocument(m, nil, -1); err != nil {
			t.Fatalf("create doc: %v", err)
		}
	}

	// Query by unit.
	docs, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		UnitID:      unit.ID,
		RequesterID: "alice",
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(docs) != 3 {
		t.Fatalf("expected 3, got %d", len(docs))
	}

	// Query by tag.
	docs, err = mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		Tags:        []string{"tag-a"},
		RequesterID: "alice",
	})
	if err != nil {
		t.Fatalf("query by tag: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1, got %d", len(docs))
	}

	// Full-text search.
	docs, err = mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		FullText:    "beta",
		RequesterID: "alice",
	})
	if err != nil {
		t.Fatalf("full-text query: %v", err)
	}
	if len(docs) != 1 || docs[0].Title != "Beta Analysis" {
		t.Fatalf("expected Beta Analysis, got %v", docs)
	}

	// Pagination.
	docs, err = mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "alice",
		Limit:       2,
		Offset:      0,
	})
	if err != nil {
		t.Fatalf("paginated query: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 (paginated), got %d", len(docs))
	}

	// bob cannot see alice's docs.
	docs, err = mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "bob",
	})
	if err != nil {
		t.Fatalf("query as bob: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("bob should see 0 docs, got %d", len(docs))
	}

	// CreatedAfter filter (future date → 0 results).
	docs, err = mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID:  "alice",
		CreatedAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("created_after query: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("expected 0 for future date filter, got %d", len(docs))
	}
}

// Package main demonstrates the HRS Document Library (doclib) layered on top of
// Velocity DB.  Run from the repo root:
//
//	go run ./examples/doclib_demo
//
// The demo exercises every major subsystem in order:
//
//  1. Org hierarchy — company → department → unit
//  2. User enrolment — two users in two different units
//  3. Document creation — owner, classification, metadata
//  4. Cross-unit access denied before sharing
//  5. Share-request approval flow
//  6. Post-approval access + share revocation
//  7. Unit switch — membership revoked, old access disappears
//  8. Document lifecycle   draft → under_review → approved → published
//  9. Flow history
// 10. Query / filter — by tag, classification, dept, full-text
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/doclib"
)

// ─────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────

func section(title string) {
	bar := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n  %s\n%s\n", bar, title, bar)
}

func check(label string, ok bool) {
	if ok {
		fmt.Printf("  ✓ %s\n", label)
	} else {
		fmt.Printf("  ✗ FAIL: %s\n", label)
		os.Exit(1)
	}
}

func mustNoErr(label string, err error) {
	if err != nil {
		fmt.Printf("  ✗ FAIL: %s — %v\n", label, err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ %s\n", label)
}

// ─────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────

func main() {
	// ── Open a fresh, temporary database ──────────────────
	dir, err := os.MkdirTemp("", "doclib-demo-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	db, err := velocity.New(dir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	mgr := doclib.NewManager(db)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║          HRS Document Library — Full Demo                ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// ── 1. Organisational hierarchy ───────────────────────
	section("1. Build org hierarchy: Company → Dept → Unit × 2")

	company, err := mgr.Org.CreateCompany("GlobalCorp", "A global enterprise", "sysop")
	mustNoErr("create company GlobalCorp", err)
	fmt.Printf("     company.ID  = %s\n", company.ID)

	dept, err := mgr.Org.CreateDepartment(company.ID, "Research & Development", "RD", "dept-head", "sysop")
	mustNoErr("create department R&D", err)
	fmt.Printf("     dept.ID     = %s\n", dept.ID)

	unit1, err := mgr.Org.CreateUnit(dept.ID, company.ID, "Core Platform", "CP", "mgr-alice")
	mustNoErr("create unit Core Platform (Unit-1)", err)
	fmt.Printf("     unit1.ID    = %s\n", unit1.ID)

	unit2, err := mgr.Org.CreateUnit(dept.ID, company.ID, "Data Science", "DS", "mgr-bob")
	mustNoErr("create unit Data Science (Unit-2)", err)
	fmt.Printf("     unit2.ID    = %s\n", unit2.ID)

	// List units
	units, err := mgr.Org.ListUnits(dept.ID)
	mustNoErr("list units in R&D", err)
	check(fmt.Sprintf("dept has 2 units (got %d)", len(units)), len(units) == 2)

	// ── 2. User enrolment ─────────────────────────────────
	section("2. Enrol users — alice → Unit-1, bob → Unit-2")

	_, err = mgr.Org.AddMember("alice", unit1.ID, "member")
	mustNoErr("enrol alice in Unit-1", err)

	_, err = mgr.Org.AddMember("bob", unit2.ID, "member")
	mustNoErr("enrol bob in Unit-2", err)

	aliceMems, _ := mgr.Org.GetMemberships("alice")
	check("alice has 1 active membership", len(aliceMems) == 1 && aliceMems[0].UnitID == unit1.ID)

	bobMems, _ := mgr.Org.GetMemberships("bob")
	check("bob has 1 active membership", len(bobMems) == 1 && bobMems[0].UnitID == unit2.ID)

	// ── 3. Create documents ───────────────────────────────
	section("3. Alice creates three documents in Unit-1")

	createDoc := func(title, classification string, tags []string) *doclib.DocumentMeta {
		meta := &doclib.DocumentMeta{
			Title:                 title,
			Description:           "Auto-generated in demo",
			DocType:               "report",
			OwnerUserID:           "alice",
			OwnerUnitID:           unit1.ID,
			OwnerDeptID:           dept.ID,
			OwnerCompanyID:        company.ID,
			ClassificationLevel:   doclib.ClassificationLevel(classification),
			Tags:                  tags,
			RequiresShareApproval: classification == string(doclib.ClassConfidential),
		}
		doc, err := mgr.Doc.CreateDocument(meta, nil, -1)
		mustNoErr("create document «"+title+"»", err)
		fmt.Printf("     doc.DocID   = %s\n", doc.DocID)
		return doc
	}

	docPublic := createDoc("Q1 Public Summary", string(doclib.ClassPublic), []string{"quarterly", "public"})
	docInternal := createDoc("Architecture Overview", string(doclib.ClassInternal), []string{"architecture", "internal"})
	docConfidential := createDoc("Salary Band Matrix", string(doclib.ClassConfidential), []string{"hr", "confidential"})

	// Alice can read her own docs.
	check("alice can read public doc", mgr.Doc.CanAccess("alice", docPublic.DocID, "read"))
	check("alice can read confidential doc (owner)", mgr.Doc.CanAccess("alice", docConfidential.DocID, "read"))

	// ── 4. Cross-unit access denied ───────────────────────
	section("4. Verify bob (Unit-2) cannot access alice's documents")

	check("bob denied read on public doc (no grant yet)", !mgr.Doc.CanAccess("bob", docPublic.DocID, "read"))
	check("bob denied read on internal doc", !mgr.Doc.CanAccess("bob", docInternal.DocID, "read"))
	check("bob denied read on confidential doc", !mgr.Doc.CanAccess("bob", docConfidential.DocID, "read"))

	// ── 5. Share request — auto-approved (internal) ───────
	section("5. Share internal doc with Unit-2 (auto-approved: classification=internal)")

	shareInternal, err := mgr.Share.CreateShare(
		docInternal.DocID, "alice",
		doclib.GrantTypeUnit, unit2.ID,
		[]string{"read"}, "collab on architecture", nil,
	)
	mustNoErr("create share request for internal doc", err)
	check("share is auto-approved (internal docs skip approval)",
		shareInternal.ApprovalStatus == doclib.ApprovalAutoApproved)
	check("bob can now read internal doc", mgr.Doc.CanAccess("bob", docInternal.DocID, "read"))
	check("bob still cannot write internal doc", !mgr.Doc.CanAccess("bob", docInternal.DocID, "write"))

	// ── 6. Share request — requires approval (confidential)
	section("6. Share confidential doc with Unit-2 — needs manager approval")

	shareConf, err := mgr.Share.CreateShare(
		docConfidential.DocID, "alice",
		doclib.GrantTypeUnit, unit2.ID,
		[]string{"read"}, "salary review", nil,
	)
	mustNoErr("create share request for confidential doc", err)
	check("share status is pending", shareConf.ApprovalStatus == doclib.ApprovalPending)
	check("bob still denied while pending", !mgr.Doc.CanAccess("bob", docConfidential.DocID, "read"))

	// Unit-1 manager approves.
	approved, err := mgr.Share.ApproveShare(shareConf.ShareID, "mgr-alice")
	mustNoErr("mgr-alice approves the share", err)
	check("share is now approved", approved.ApprovalStatus == doclib.ApprovalApproved)
	check("bob can read confidential doc after approval", mgr.Doc.CanAccess("bob", docConfidential.DocID, "read"))

	// Revoke the confidential share.
	_, err = mgr.Share.RevokeShare(shareConf.ShareID, "alice")
	mustNoErr("alice revokes the confidential share", err)
	check("bob denied after revocation", !mgr.Doc.CanAccess("bob", docConfidential.DocID, "read"))

	// ── 7. Unit switch ────────────────────────────────────
	section("7. Alice switches unit: Unit-1 → Unit-2 (old access revoked)")

	// Revoke Unit-2's grant on the internal doc first so test is clean.
	_, _ = mgr.Share.RevokeShare(shareInternal.ShareID, "alice")

	// Deactivate alice's Unit-1 membership.
	err = mgr.Org.RemoveMember("alice", unit1.ID)
	mustNoErr("remove alice from Unit-1", err)

	mems, _ := mgr.Org.GetMemberships("alice")
	check("alice has 0 active memberships after removal", len(mems) == 0)

	// Add alice to Unit-2.
	_, err = mgr.Org.AddMember("alice", unit2.ID, "member")
	mustNoErr("add alice to Unit-2", err)

	mems, _ = mgr.Org.GetMemberships("alice")
	check("alice has 1 membership now (Unit-2)", len(mems) == 1 && mems[0].UnitID == unit2.ID)

	// Alice is still the document owner — owner check is not unit-based.
	check("alice still owns docs (owner flag unchanged)", mgr.Doc.CanAccess("alice", docPublic.DocID, "read"))

	// ── 8. Lifecycle transitions ──────────────────────────
	section("8. Lifecycle: draft → under_review → approved → published")

	// Use the public doc as the workflow subject.
	docID := docPublic.DocID

	// Check initial status.
	fresh, _ := mgr.Doc.GetDocument(docID)
	check(fmt.Sprintf("document starts as 'draft' (got '%s')", fresh.Status), fresh.Status == doclib.StatusDraft)

	d, err := mgr.Lifecycle.Submit(docID, "alice", "10.0.0.1", "ready for review")
	mustNoErr("Submit (draft → under_review)", err)
	check("status is now under_review", d.Status == doclib.StatusUnderReview)

	d, err = mgr.Lifecycle.Approve(docID, "alice", "10.0.0.1", "looks good")
	mustNoErr("Approve (under_review → approved)", err)
	check("status is now approved", d.Status == doclib.StatusApproved)

	d, err = mgr.Lifecycle.Publish(docID, "alice", "10.0.0.1", "going live")
	mustNoErr("Publish (approved → published)", err)
	check("status is now published", d.Status == doclib.StatusPublished)

	// Archive a different doc.
	_, err = mgr.Lifecycle.Archive(docInternal.DocID, "alice", "10.0.0.1", "end of quarter")
	mustNoErr("Archive internal doc", err)

	// ── 9. Flow history ───────────────────────────────────
	section("9. Retrieve flow history for the public doc")

	history, err := mgr.Lifecycle.GetHistory(docID)
	mustNoErr("get history", err)
	check(fmt.Sprintf("history has 3 events (got %d)", len(history)), len(history) == 3)
	for i, ev := range history {
		fmt.Printf("  [%d] %s → %s  by=%s  comment=%q\n",
			i+1, ev.FromStatus, ev.ToStatus, ev.Actor, ev.Comment)
	}

	// ── 10. Query & filter ────────────────────────────────
	section("10. Query documents with various filters")

	// Create one more doc for richer query surface.
	createDoc("Security Audit Report", string(doclib.ClassRestricted), []string{"security", "audit"})

	// --- by owner_unit_id (alice is now in Unit-2, but is still owner of Unit-1 docs)
	all, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "alice",
	})
	mustNoErr("query all docs (as alice)", err)
	check(fmt.Sprintf("alice sees 4 documents (owns all, got %d)", len(all)), len(all) == 4)

	// --- by tag
	byTag, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		Tags:        []string{"quarterly"},
		RequesterID: "alice",
	})
	mustNoErr("query by tag 'quarterly'", err)
	check(fmt.Sprintf("1 doc tagged 'quarterly' (got %d)", len(byTag)), len(byTag) == 1)
	check("tagged doc is the public summary", byTag[0].Title == "Q1 Public Summary")

	// --- by classification
	byClass, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		ClassificationLevel: doclib.ClassConfidential,
		RequesterID:         "alice",
	})
	mustNoErr("query by classification=confidential", err)
	check(fmt.Sprintf("1 confidential doc (got %d)", len(byClass)), len(byClass) == 1)

	// --- by dept_id
	byDept, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		DeptID:      dept.ID,
		RequesterID: "alice",
	})
	mustNoErr("query by dept_id", err)
	check(fmt.Sprintf("all 4 docs belong to R&D dept (got %d)", len(byDept)), len(byDept) == 4)

	// --- full-text
	byText, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		FullText:    "architecture",
		RequesterID: "alice",
	})
	mustNoErr("full-text search 'architecture'", err)
	check(fmt.Sprintf("1 result for 'architecture' (got %d)", len(byText)), len(byText) == 1)
	check("result is the Architecture Overview", byText[0].Title == "Architecture Overview")

	// --- bob can only see what's been granted (internal grant was revoked)
	byBob, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "bob",
	})
	mustNoErr("query all docs as bob", err)
	check(fmt.Sprintf("bob sees 0 docs (all grants revoked, got %d)", len(byBob)), len(byBob) == 0)

	// --- pagination
	page1, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "alice",
		Limit:       2,
		Offset:      0,
	})
	mustNoErr("paginated query page 1 (limit=2)", err)
	check(fmt.Sprintf("page 1 has 2 docs (got %d)", len(page1)), len(page1) == 2)

	page2, err := mgr.Doc.QueryDocuments(doclib.DocumentFilter{
		RequesterID: "alice",
		Limit:       2,
		Offset:      2,
	})
	mustNoErr("paginated query page 2 (offset=2, limit=2)", err)
	check(fmt.Sprintf("page 2 has 2 docs (got %d)", len(page2)), len(page2) == 2)

	// ── Summary ───────────────────────────────────────────
	section("All scenarios passed")
	fmt.Println()
	fmt.Println("  ✓ Org hierarchy created and listed")
	fmt.Println("  ✓ Users enrolled in separate units")
	fmt.Println("  ✓ Documents created with owner-only ACL")
	fmt.Println("  ✓ Cross-unit access correctly denied")
	fmt.Println("  ✓ Internal share auto-approved → bob gained access")
	fmt.Println("  ✓ Confidential share required + got manager approval")
	fmt.Println("  ✓ Share revocation removed access immediately")
	fmt.Println("  ✓ Unit switch deactivated old membership")
	fmt.Println("  ✓ Lifecycle: draft → under_review → approved → published")
	fmt.Println("  ✓ Flow history contains all transition events")
	fmt.Println("  ✓ Query: by tag / classification / dept / full-text / pagination")
	fmt.Println()
}

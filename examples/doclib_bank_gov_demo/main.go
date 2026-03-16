// Package main demonstrates the HRS Document Library bank/government dispatch
// capabilities layered on top of Velocity DB.  Run from the repo root:
//
//	go run ./examples/doclib_bank_gov_demo
//
// The demo exercises:
//
//  1. Org setup — bank, government ministry, hospital unit
//  2. Sensitive document creation with restricted/top-secret classification
//  3. Envelope-based dispatch to a bank (legal custody proof)
//  4. Envelope-based dispatch to a government ministry (with time-lock)
//  5. Multi-recipient dispatch to external services
//  6. Recipient acknowledges dispatch (custody chain updated)
//  7. Dispatch recalled with custody note
//  8. Full per-document access chain — every read, share, dispatch logged
//  9. Hash-linked chain integrity verification
// 10. Audit chain summary stats (actors, actions, outcomes)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/doclib"
)

// ─────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────

func section(title string) {
	bar := strings.Repeat("─", 64)
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
	ctx := context.Background()

	// ── Open a fresh, temporary database ──────────────────
	dir, err := os.MkdirTemp("", "doclib-bank-gov-*")
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
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║   HRS Document Library — Bank / Government Dispatch Demo    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// ── 1. Organisational hierarchy ───────────────────────
	section("1. Build org: National Health Authority → Records Dept → Clinical Unit")

	company, err := mgr.Org.CreateCompany("National Health Authority", "Public health regulator", "sysop")
	mustNoErr("create National Health Authority", err)

	dept, err := mgr.Org.CreateDepartment(company.ID, "Medical Records", "MED-REC", "dr-head", "sysop")
	mustNoErr("create Medical Records dept", err)

	unit, err := mgr.Org.CreateUnit(dept.ID, company.ID, "Clinical Data Unit", "CDU", "dr-manager")
	mustNoErr("create Clinical Data Unit", err)

	_, err = mgr.Org.AddMember("dr-alice", unit.ID, "member")
	mustNoErr("enrol dr-alice in Clinical Data Unit", err)

	_, err = mgr.Org.AddMember("dr-bob", unit.ID, "member")
	mustNoErr("enrol dr-bob in Clinical Data Unit", err)

	fmt.Printf("     company.ID = %s\n", company.ID)
	fmt.Printf("     dept.ID    = %s\n", dept.ID)
	fmt.Printf("     unit.ID    = %s\n", unit.ID)

	// ── 2. Create sensitive documents ─────────────────────
	section("2. Create two sensitive documents: Restricted patient record, Top-Secret drug trial")

	patientDoc, err := mgr.Doc.CreateDocument(&doclib.DocumentMeta{
		Title:                 "Patient Record — File #PR-2024-001",
		Description:           "Complete patient history including lab results and imaging",
		DocType:               "patient_record",
		ContentType:           "application/pdf",
		OwnerUserID:           "dr-alice",
		OwnerUnitID:           unit.ID,
		OwnerDeptID:           dept.ID,
		OwnerCompanyID:        company.ID,
		ClassificationLevel:   doclib.ClassRestricted,
		Tags:                  []string{"patient", "confidential", "lab"},
		RequiresShareApproval: true,
	}, nil, -1)
	mustNoErr("create patient record (restricted)", err)
	fmt.Printf("     patientDoc.DocID  = %s\n", patientDoc.DocID)

	trialDoc, err := mgr.Doc.CreateDocument(&doclib.DocumentMeta{
		Title:                 "Phase-III Drug Trial Results — DrugX",
		Description:           "Unpublished clinical trial outcomes for regulatory submission",
		DocType:               "clinical_trial",
		ContentType:           "application/pdf",
		OwnerUserID:           "dr-alice",
		OwnerUnitID:           unit.ID,
		OwnerDeptID:           dept.ID,
		OwnerCompanyID:        company.ID,
		ClassificationLevel:   doclib.ClassTopSecret,
		Tags:                  []string{"trial", "drug", "phase3"},
		RequiresShareApproval: true,
	}, nil, -1)
	mustNoErr("create drug trial report (top_secret)", err)
	fmt.Printf("     trialDoc.DocID    = %s\n", trialDoc.DocID)

	// Owner can always read.
	check("dr-alice can read patient record (owner)", mgr.Doc.CanAccess("dr-alice", patientDoc.DocID, "read"))
	check("dr-bob cannot read patient record (no grant)", !mgr.Doc.CanAccess("dr-bob", patientDoc.DocID, "read"))

	// ── 3. Dispatch patient record to a bank (insurance claim) ────
	section("3. Dispatch patient record to HealthFirst Bank — insurance claim processing")

	expiry := time.Now().UTC().Add(30 * 24 * time.Hour) // 30 days
	bankDispatch, err := mgr.Dispatch.SendDispatch(ctx, doclib.DispatchRequest{
		DocID:  patientDoc.DocID,
		SentBy: "dr-alice",
		Recipients: []doclib.DispatchRecipient{
			{
				Type:        doclib.RecipientBank,
				ID:          "healthfirst-bank-001",
				Name:        "HealthFirst Insurance Bank",
				Reference:   "CLAIM-2024-INS-78912",
				Permissions: []string{"read"},
			},
		},
		Purpose:   "Insurance claim verification for patient admission",
		CaseRef:   "CLAIM-2024-INS-78912",
		ExpiresAt: &expiry,
		LegalNote: "Document provided under Health Data Protection Act §12(3). Recipient must not further disclose.",
		Tags: map[string]string{
			"claim_type": "hospital_admission",
			"policy_no":  "HFB-POL-445522",
		},
	}, "10.0.1.1")
	mustNoErr("dispatch patient record to HealthFirst Bank", err)
	fmt.Printf("     bankDispatch.DispatchID  = %s\n", bankDispatch.DispatchID)
	fmt.Printf("     bankDispatch.EnvelopeID  = %s\n", bankDispatch.EnvelopeID)
	check("dispatch status is 'sent'", bankDispatch.Status == doclib.DispatchStatusSent)
	check("dispatch has 1 recipient", len(bankDispatch.Recipients) == 1)
	check("recipient type is bank", bankDispatch.Recipients[0].Type == doclib.RecipientBank)

	// ── 4. Dispatch drug trial to government ministry (time-locked) ───
	section("4. Dispatch drug trial to Ministry of Health — regulatory submission (time-locked)")

	unlockDate := time.Now().UTC().Add(14 * 24 * time.Hour) // embargo: 14 days
	govDispatch, err := mgr.Dispatch.SendDispatch(ctx, doclib.DispatchRequest{
		DocID:  trialDoc.DocID,
		SentBy: "dr-alice",
		Recipients: []doclib.DispatchRecipient{
			{
				Type:        doclib.RecipientGovernment,
				ID:          "ministry-of-health-001",
				Name:        "Ministry of Health — Drug Approval Division",
				Reference:   "REG-SUB-2024-DRUGX-001",
				Permissions: []string{"read", "approve"},
			},
		},
		Purpose:   "Regulatory submission for Phase-III drug approval",
		CaseRef:   "REG-SUB-2024-DRUGX-001",
		ExpiresAt: &unlockDate,
		TimeLock:  true,
		LegalNote: "Embargoed until regulatory review period ends. Access permitted post unlock date.",
		Tags: map[string]string{
			"submission_type": "phase3_drug_approval",
			"drug_code":       "DRUGX",
		},
	}, "10.0.1.1")
	mustNoErr("dispatch drug trial to Ministry of Health (time-locked)", err)
	fmt.Printf("     govDispatch.DispatchID   = %s\n", govDispatch.DispatchID)
	fmt.Printf("     govDispatch.EnvelopeID   = %s\n", govDispatch.EnvelopeID)
	check("gov dispatch status is 'sent'", govDispatch.Status == doclib.DispatchStatusSent)

	// ── 5. Multi-recipient dispatch to external services ──
	section("5. Multi-recipient dispatch: patient record → lab + radiology centre")

	multiDispatch, err := mgr.Dispatch.SendDispatch(ctx, doclib.DispatchRequest{
		DocID:  patientDoc.DocID,
		SentBy: "dr-alice",
		Recipients: []doclib.DispatchRecipient{
			{
				Type:        doclib.RecipientService,
				ID:          "central-lab-001",
				Name:        "Central Pathology Laboratory",
				Reference:   "LAB-REQ-2024-7745",
				Permissions: []string{"read"},
			},
			{
				Type:        doclib.RecipientService,
				ID:          "radiology-centre-002",
				Name:        "City Radiology Centre",
				Reference:   "RAD-REQ-2024-3312",
				Permissions: []string{"read"},
			},
		},
		Purpose: "Referred for specialist pathology and imaging review",
		CaseRef: "CASE-2024-ALICE-001",
	}, "10.0.1.2")
	mustNoErr("multi-recipient dispatch to lab + radiology", err)
	check("multi-dispatch has 2 recipients", len(multiDispatch.Recipients) == 2)
	fmt.Printf("     multiDispatch.DispatchID = %s\n", multiDispatch.DispatchID)

	// ── 6. Bank acknowledges the dispatch ─────────────────
	section("6. HealthFirst Bank acknowledges receipt of patient record")

	ackedDispatch, err := mgr.Dispatch.AcknowledgeDispatch(ctx, bankDispatch.DispatchID, "healthfirst-claims-officer", "10.22.33.44")
	mustNoErr("HealthFirst Bank acknowledges dispatch", err)
	check("dispatch status is now 'acknowledged'", ackedDispatch.Status == doclib.DispatchStatusAcknowledged)
	check("ack actor is recorded", ackedDispatch.AckBy == "healthfirst-claims-officer")
	check("ack timestamp set", ackedDispatch.AckAt != nil)
	fmt.Printf("     acked at: %s\n", ackedDispatch.AckAt.Format(time.RFC3339))

	// ── 7. Recall the multi-recipient dispatch ─────────────
	section("7. Recall the multi-recipient dispatch (lab referral cancelled)")

	recalledDispatch, err := mgr.Dispatch.RecallDispatch(
		ctx,
		multiDispatch.DispatchID,
		"dr-alice",
		"Patient transferred to another facility — referral no longer required",
		"10.0.1.1",
	)
	mustNoErr("dr-alice recalls lab/radiology dispatch", err)
	check("dispatch status is 'recalled'", recalledDispatch.Status == doclib.DispatchStatusRecalled)
	check("recall actor recorded", recalledDispatch.RecalledBy == "dr-alice")
	check("recall note stored", recalledDispatch.RecallNote != "")
	fmt.Printf("     recall note: %s\n", recalledDispatch.RecallNote)

	// ── 8. Retrieve Velocity envelope with full custody chain ──
	section("8. Retrieve Velocity envelope for bank dispatch (full custody chain)")

	envelope, err := mgr.Dispatch.GetEnvelope(ctx, bankDispatch.DispatchID, "dr-alice")
	mustNoErr("dr-alice retrieves bank dispatch envelope", err)
	check("envelope ID matches", envelope.EnvelopeID == bankDispatch.EnvelopeID)
	fmt.Printf("     envelope.Label          = %s\n", envelope.Label)
	fmt.Printf("     envelope.Type           = %s\n", envelope.Type)
	fmt.Printf("     custody events recorded = %d\n", len(envelope.CustodyLedger))
	check("envelope has custody events", len(envelope.CustodyLedger) >= 1)

	// Unauthorized actor cannot access envelope.
	_, err = mgr.Dispatch.GetEnvelope(ctx, bankDispatch.DispatchID, "intruder")
	check("intruder cannot access envelope (access denied)", err != nil)

	// ── 9. Full per-document access chain ─────────────────
	section("9. Per-document access chain — every operation on patient record")

	chain, err := mgr.Audit.GetChain(patientDoc.DocID)
	mustNoErr("retrieve access chain for patient record", err)
	fmt.Printf("     total chain events: %d\n", len(chain))
	check("chain is non-empty", len(chain) > 0)

	fmt.Println("\n  Event log:")
	for i, ev := range chain {
		fmt.Printf("  [%2d] %-30s %-12s actor=%-28s detail=%s\n",
			i+1, ev.Action, ev.Outcome, ev.Actor, ev.Detail)
	}

	// ── 10. Chain integrity verification ──────────────────
	section("10. Hash-linked chain integrity — every event verified")

	summary, err := mgr.Audit.GetChainSummary(patientDoc.DocID)
	mustNoErr("get access chain summary for patient record", err)
	check(fmt.Sprintf("chain integrity = '%s'", summary.ChainIntegrity),
		summary.ChainIntegrity == "verified")
	check(fmt.Sprintf("total events = %d", summary.TotalEvents), summary.TotalEvents > 0)
	check("unique actors recorded", summary.UniqueActors >= 1)

	fmt.Printf("\n  Chain Summary:\n")
	fmt.Printf("    Total events  : %d\n", summary.TotalEvents)
	fmt.Printf("    Unique actors : %d\n", summary.UniqueActors)
	fmt.Printf("    Chain integrity: %s\n", summary.ChainIntegrity)
	if summary.FirstEventAt != nil {
		fmt.Printf("    First event   : %s\n", summary.FirstEventAt.Format(time.RFC3339))
	}
	if summary.LastEventAt != nil {
		fmt.Printf("    Last event    : %s\n", summary.LastEventAt.Format(time.RFC3339))
	}

	fmt.Println("\n  Events by action:")
	for action, count := range summary.EventsByAction {
		fmt.Printf("    %-35s %d\n", action, count)
	}
	fmt.Println("\n  Events by outcome:")
	for outcome, count := range summary.EventsByOutcome {
		fmt.Printf("    %-12s %d\n", outcome, count)
	}

	// Also verify trial doc chain.
	trialSummary, err := mgr.Audit.GetChainSummary(trialDoc.DocID)
	mustNoErr("get access chain summary for drug trial doc", err)
	check(fmt.Sprintf("trial doc chain integrity = '%s'", trialSummary.ChainIntegrity),
		trialSummary.ChainIntegrity == "verified")

	// ── 11. List all dispatches for patient record ─────────
	section("11. List all dispatches for patient record")

	dispatches, err := mgr.Dispatch.ListDispatches(patientDoc.DocID)
	mustNoErr("list dispatches for patient record", err)
	check(fmt.Sprintf("patient record has 2 dispatches (got %d)", len(dispatches)), len(dispatches) == 2)

	for _, d := range dispatches {
		fmt.Printf("  dispatch=%s status=%-15s recipients=%d case=%s\n",
			d.DispatchID[:8]+"…",
			d.Status,
			len(d.Recipients),
			d.CaseRef,
		)
	}

	// ── Summary ───────────────────────────────────────────
	section("All scenarios passed")
	fmt.Println()
	fmt.Println("  ✓ Org hierarchy: National Health Authority → Medical Records → Clinical Data Unit")
	fmt.Println("  ✓ Restricted patient record + Top-Secret drug trial created")
	fmt.Println("  ✓ Patient record dispatched to HealthFirst Bank (insurance claim)")
	fmt.Println("  ✓ Drug trial dispatched to Ministry of Health (time-locked, regulatory)")
	fmt.Println("  ✓ Multi-recipient dispatch to lab + radiology centre")
	fmt.Println("  ✓ Bank acknowledged receipt (custody chain updated)")
	fmt.Println("  ✓ Lab/radiology dispatch recalled (custody chain records recall)")
	fmt.Println("  ✓ Full Velocity envelope retrieved with custody chain for bank dispatch")
	fmt.Println("  ✓ Unauthorized actor denied envelope access")
	fmt.Println("  ✓ Per-document hash-linked access chain captured every operation")
	fmt.Println("  ✓ Chain integrity verified (SHA-256 hash links intact)")
	fmt.Println("  ✓ Audit summary: total events, unique actors, events by action/outcome")
	fmt.Println("  ✓ All dispatches listed per document")
	fmt.Println()
}

//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	fmt.Println("=== Velocity Secure Envelope System Demo ===\n")

	// SENDER SIDE: Initialize sender's database
	fmt.Println("📤 SENDER: Creating Court Evidence Envelope")
	fmt.Println("==========================================================")
	senderDB, err := velocity.NewWithConfig(velocity.Config{
		Path: "./sender_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer senderDB.Close()

	// Sender creates envelope and exports to file
	envelopeFile := senderCreateAndExportEvidence(senderDB)

	// RECIPIENT SIDE: Initialize recipient's database (separate system)
	fmt.Println("\n📥 RECIPIENT: Importing Evidence Envelope")
	fmt.Println("==========================================================")
	recipientDB, err := velocity.NewWithConfig(velocity.Config{
		Path: "./recipient_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer recipientDB.Close()

	// Recipient imports envelope from file
	envelopeID := recipientImportAndAccessEvidence(recipientDB, envelopeFile)

	fmt.Println("\n🔍 INVESTIGATOR: Recording Tamper Analysis")
	fmt.Println("==========================================================")
	investigatorAnalyze(recipientDB, envelopeID)

	fmt.Println("\n⏰ LEGAL AUTHORITY: Approving Time-Lock Release")
	fmt.Println("==========================================================")
	legalAuthorityUnlock(recipientDB, envelopeID)

	fmt.Println("\n📋 AUDITOR: Reviewing Full Chain of Custody")
	fmt.Println("==========================================================")
	auditorReview(recipientDB, envelopeID)
}

// senderCreateEvidence demonstrates how a sender creates a secure envelope
func senderCreateEvidence(db *velocity.DB) string {
	ctx := context.Background()

	// Step 1: Prepare the evidence data
	evidenceData := map[string]interface{}{
		"case_number": "CR-2026-001234",
		"evidence_id": "ITEM-789",
		"description":  "CCTV footage from crime scene",
		"location":     "123 Main Street, Camera #5",
		"timestamp":    "2026-01-20T14:30:00Z",
		"file_hash":    "sha256:abc123def456...",
	}
	evidenceJSON, _ := json.Marshal(evidenceData)

	// Step 2: Define time-lock policy (evidence locked until court date)
	courtDate := time.Now().Add(30 * 24 * time.Hour) // 30 days from now
	timeLockPolicy := velocity.TimeLockPolicy{
		Mode:             "legal_delay",
		UnlockNotBefore:  courtDate,
		MinDelaySeconds:  7 * 24 * 3600, // Minimum 7 days
		LegalCondition:   "Court order required for early access",
		EscrowSigners:    []string{"judge@court.gov", "prosecutor@da.gov"},
	}

	// Step 3: Create fingerprint policy for access control
	fingerprintPolicy := velocity.FingerprintPolicy{
		Required:         true,
		MatchingStrategy: "threshold_90",
		AuthorizedFingerprints: []string{
			"fp:detective-john-doe",
			"fp:prosecutor-jane-smith",
		},
	}

	// Step 4: Configure tamper detection
	tamperPolicy := velocity.TamperPolicy{
		Analyzer:    "velocity-ml-v1",
		Sensitivity: "high",
		Offline:     true,
	}

	// Step 5: Enable cold storage
	coldStoragePolicy := velocity.ColdStoragePolicy{
		Enabled:      true,
		StorageClass: "evidence_archive",
		Interval:     "daily",
	}

	// Step 6: Create the envelope request
	request := &velocity.EnvelopeRequest{
		Label:          "CCTV Evidence - Case CR-2026-001234",
		Type:           velocity.EnvelopeTypeCCTVArchive,
		EvidenceClass:  "digital_video",
		CreatedBy:      "officer-smith-badge-5678",
		CaseReference:  "CR-2026-001234",
		FingerprintSignature: "fp:officer-smith-5678",
		IntakeLocation: "Evidence Room 3, Police HQ",
		Notes:          "Original CCTV footage secured at scene",
		Payload: velocity.EnvelopePayload{
			Kind:         "file",
			ObjectPath:   "evidence/cctv/case-001234/camera5.mp4",
			InlineData:   evidenceJSON,
			EncodingHint: "json+base64",
			Metadata: map[string]string{
				"duration_seconds": "180",
				"resolution":       "1920x1080",
				"codec":            "h264",
			},
		},
		Policies: velocity.EnvelopePolicies{
			TimeLock:    timeLockPolicy,
			Fingerprint: fingerprintPolicy,
			Tamper:      tamperPolicy,
			ColdStorage: coldStoragePolicy,
		},
		Tags: map[string]string{
			"case_type":  "robbery",
			"priority":   "high",
			"department": "homicide",
		},
	}

	// Step 7: Create the envelope
	envelope, err := db.CreateEnvelope(ctx, request)
	if err != nil {
		log.Fatalf("Failed to create envelope: %v", err)
	}

	fmt.Printf("✅ Envelope Created\n")
	fmt.Printf("   ID: %s\n", envelope.EnvelopeID)
	fmt.Printf("   Label: %s\n", envelope.Label)
	fmt.Printf("   Status: %s\n", envelope.Status)
	fmt.Printf("   Time-Lock Until: %s\n", envelope.TimeLockStatus.UnlockNotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Payload Hash: %s\n", envelope.Integrity.PayloadHash[:16]+"...")
	fmt.Printf("   Custody Events: %d\n", len(envelope.CustodyLedger))

	// Step 8: Export envelope to file for sharing
	exportPath := "./evidence_transfer/" + envelope.EnvelopeID + ".envelope"
	if err := db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath); err != nil {
		log.Fatalf("Failed to export envelope: %v", err)
	}

	fmt.Printf("\n📦 Envelope Exported\n")
	fmt.Printf("   File: %s\n", exportPath)
	fmt.Printf("   Ready to share with recipients\n")

	return exportPath
}

// recipientImportAndAccessEvidence demonstrates how recipient imports and accesses an envelope file
func recipientImportAndAccessEvidence(db *velocity.DB, envelopeFile string) string {
	ctx := context.Background()

	// Step 1: Import the envelope from file
	envelope, err := db.ImportEnvelope(ctx, envelopeFile)
	if err != nil {
		log.Fatalf("Failed to import envelope: %v", err)
	}

	fmt.Printf("📦 Envelope Imported from File\n")
	fmt.Printf("   Source: %s\n", envelopeFile)
	fmt.Printf("   ID: %s\n", envelope.EnvelopeID)
	fmt.Printf("   Label: %s\n", envelope.Label)
	fmt.Printf("   Type: %s\n", envelope.Type)
	fmt.Printf("   Created: %s\n", envelope.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Created By: %s\n", envelope.CreatedBy)

	// Step 2: Check time-lock status
	if envelope.TimeLockStatus.Active {
		fmt.Printf("\n⏰ TIME-LOCK ACTIVE\n")
		fmt.Printf("   Unlock Not Before: %s\n", envelope.TimeLockStatus.UnlockNotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Legal Condition: %s\n", envelope.Policies.TimeLock.LegalCondition)
		fmt.Printf("   ⚠️  Cannot access payload until time-lock is released\n")
	}

	// Step 3: Check fingerprint requirements
	if envelope.Policies.Fingerprint.Required {
		fmt.Printf("\n🔐 FINGERPRINT VERIFICATION REQUIRED\n")
		fmt.Printf("   Strategy: %s\n", envelope.Policies.Fingerprint.MatchingStrategy)
		fmt.Printf("   Authorized: %d fingerprints\n", len(envelope.Policies.Fingerprint.AuthorizedFingerprints))
	}

	// Step 4: Verify integrity
	fmt.Printf("\n🔒 INTEGRITY VERIFICATION\n")
	fmt.Printf("   Payload Hash: %s\n", envelope.Integrity.PayloadHash[:16]+"...")
	fmt.Printf("   Ledger Root: %s\n", envelope.Integrity.LedgerRoot[:16]+"...")
	fmt.Printf("   Time Seal: %s\n", envelope.Integrity.TimeSeal.Hash[:16]+"...")

	// Step 5: Record access in custody chain
	accessEvent := &velocity.CustodyEvent{
		Actor:            "detective-john-doe",
		ActorFingerprint: "fp:detective-john-doe",
		Action:           "envelope.imported",
		Location:         "Detective Office, Terminal 42",
		Notes:            "Envelope imported for case preparation",
		EvidenceState:    "under_review",
	}
	envelope, err = db.AppendCustodyEvent(ctx, envelope.EnvelopeID, accessEvent)
	if err != nil {
		log.Fatalf("Failed to append custody event: %v", err)
	}

	fmt.Printf("\n📝 Custody Event Recorded\n")
	fmt.Printf("   Total Events: %d\n", len(envelope.CustodyLedger))
	fmt.Printf("   Latest Action: %s by %s\n", accessEvent.Action, accessEvent.Actor)

	return envelope.EnvelopeID
}

// senderCreateAndExportEvidence demonstrates how a sender creates and exports a secure envelope
func senderCreateAndExportEvidence(db *velocity.DB) string {
	ctx := context.Background()

	// Step 1: Prepare the evidence data
	evidenceData := map[string]interface{}{
		"case_number": "CR-2026-001234",
		"evidence_id": "ITEM-789",
		"description":  "CCTV footage from crime scene",
		"location":     "123 Main Street, Camera #5",
		"timestamp":    "2026-01-20T14:30:00Z",
		"file_hash":    "sha256:abc123def456...",
	}
	evidenceJSON, _ := json.Marshal(evidenceData)

	// Step 2: Define time-lock policy (evidence locked until court date)
	courtDate := time.Now().Add(30 * 24 * time.Hour) // 30 days from now
	timeLockPolicy := velocity.TimeLockPolicy{
		Mode:             "legal_delay",
		UnlockNotBefore:  courtDate,
		MinDelaySeconds:  7 * 24 * 3600, // Minimum 7 days
		LegalCondition:   "Court order required for early access",
		EscrowSigners:    []string{"judge@court.gov", "prosecutor@da.gov"},
	}

	// Step 3: Create fingerprint policy for access control
	fingerprintPolicy := velocity.FingerprintPolicy{
		Required:         true,
		MatchingStrategy: "threshold_90",
		AuthorizedFingerprints: []string{
			"fp:detective-john-doe",
			"fp:prosecutor-jane-smith",
		},
	}

	// Step 4: Configure tamper detection
	tamperPolicy := velocity.TamperPolicy{
		Analyzer:    "velocity-ml-v1",
		Sensitivity: "high",
		Offline:     true,
	}

	// Step 5: Enable cold storage
	coldStoragePolicy := velocity.ColdStoragePolicy{
		Enabled:      true,
		StorageClass: "evidence_archive",
		Interval:     "daily",
	}

	// Step 6: Create the envelope request
	request := &velocity.EnvelopeRequest{
		Label:          "CCTV Evidence - Case CR-2026-001234",
		Type:           velocity.EnvelopeTypeCCTVArchive,
		EvidenceClass:  "digital_video",
		CreatedBy:      "officer-smith-badge-5678",
		CaseReference:  "CR-2026-001234",
		FingerprintSignature: "fp:officer-smith-5678",
		IntakeLocation: "Evidence Room 3, Police HQ",
		Notes:          "Original CCTV footage secured at scene",
		Payload: velocity.EnvelopePayload{
			Kind:         "file",
			ObjectPath:   "evidence/cctv/case-001234/camera5.mp4",
			InlineData:   evidenceJSON,
			EncodingHint: "json+base64",
			Metadata: map[string]string{
				"duration_seconds": "180",
				"resolution":       "1920x1080",
				"codec":            "h264",
			},
		},
		Policies: velocity.EnvelopePolicies{
			TimeLock:    timeLockPolicy,
			Fingerprint: fingerprintPolicy,
			Tamper:      tamperPolicy,
			ColdStorage: coldStoragePolicy,
		},
		Tags: map[string]string{
			"case_type":  "robbery",
			"priority":   "high",
			"department": "homicide",
		},
	}

	// Step 7: Create the envelope
	envelope, err := db.CreateEnvelope(ctx, request)
	if err != nil {
		log.Fatalf("Failed to create envelope: %v", err)
	}

	fmt.Printf("✅ Envelope Created\n")
	fmt.Printf("   ID: %s\n", envelope.EnvelopeID)
	fmt.Printf("   Label: %s\n", envelope.Label)
	fmt.Printf("   Status: %s\n", envelope.Status)
	fmt.Printf("   Time-Lock Until: %s\n", envelope.TimeLockStatus.UnlockNotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Payload Hash: %s\n", envelope.Integrity.PayloadHash[:16]+"...")
	fmt.Printf("   Custody Events: %d\n", len(envelope.CustodyLedger))

	// Step 8: Export envelope to file for sharing
	exportPath := "./evidence_transfer/" + envelope.EnvelopeID + ".envelope"
	if err := db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath); err != nil {
		log.Fatalf("Failed to export envelope: %v", err)
	}

	fmt.Printf("\n📦 Envelope Exported\n")
	fmt.Printf("   File: %s\n", exportPath)
	fmt.Printf("   Ready to share with recipients\n")

	return exportPath
}

// recipientAccessEvidence demonstrates how a recipient accesses an envelope
func recipientAccessEvidence(db *velocity.DB, envelopeID string) {
	ctx := context.Background()

	// Step 1: Load the envelope
	envelope, err := db.LoadEnvelope(ctx, envelopeID)
	if err != nil {
		log.Fatalf("Failed to load envelope: %v", err)
	}

	fmt.Printf("📦 Envelope Retrieved\n")
	fmt.Printf("   Label: %s\n", envelope.Label)
	fmt.Printf("   Type: %s\n", envelope.Type)
	fmt.Printf("   Created: %s\n", envelope.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Created By: %s\n", envelope.CreatedBy)

	// Step 2: Check time-lock status
	if envelope.TimeLockStatus.Active {
		fmt.Printf("\n⏰ TIME-LOCK ACTIVE\n")
		fmt.Printf("   Unlock Not Before: %s\n", envelope.TimeLockStatus.UnlockNotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Legal Condition: %s\n", envelope.Policies.TimeLock.LegalCondition)
		fmt.Printf("   ⚠️  Cannot access payload until time-lock is released\n")
	}

	// Step 3: Check fingerprint requirements
	if envelope.Policies.Fingerprint.Required {
		fmt.Printf("\n🔐 FINGERPRINT VERIFICATION REQUIRED\n")
		fmt.Printf("   Strategy: %s\n", envelope.Policies.Fingerprint.MatchingStrategy)
		fmt.Printf("   Authorized: %d fingerprints\n", len(envelope.Policies.Fingerprint.AuthorizedFingerprints))
	}

	// Step 4: Verify integrity
	fmt.Printf("\n🔒 INTEGRITY VERIFICATION\n")
	fmt.Printf("   Payload Hash: %s\n", envelope.Integrity.PayloadHash[:16]+"...")
	fmt.Printf("   Ledger Root: %s\n", envelope.Integrity.LedgerRoot[:16]+"...")
	fmt.Printf("   Time Seal: %s\n", envelope.Integrity.TimeSeal.Hash[:16]+"...")

	// Step 5: Record access in custody chain
	accessEvent := &velocity.CustodyEvent{
		Actor:            "detective-john-doe",
		ActorFingerprint: "fp:detective-john-doe",
		Action:           "envelope.accessed",
		Location:         "Detective Office, Terminal 42",
		Notes:            "Initial review for case preparation",
		EvidenceState:    "under_review",
	}
	envelope, err = db.AppendCustodyEvent(ctx, envelopeID, accessEvent)
	if err != nil {
		log.Fatalf("Failed to append custody event: %v", err)
	}

	fmt.Printf("\n📝 Custody Event Recorded\n")
	fmt.Printf("   Total Events: %d\n", len(envelope.CustodyLedger))
	fmt.Printf("   Latest Action: %s by %s\n", accessEvent.Action, accessEvent.Actor)
}

// investigatorAnalyze demonstrates tamper detection workflow
func investigatorAnalyze(db *velocity.DB, envelopeID string) {
	ctx := context.Background()

	// Simulate offline AI tamper analysis
	tamperSignal := &velocity.TamperSignal{
		Analyzer:        "velocity-ml-v1",
		AnalyzerVersion: "1.2.3",
		Score:           0.05, // Low score = no tampering detected
		Threshold:       0.75,
		Offline:         true,
		Notes: []string{
			"Hash chain integrity verified",
			"No anomalous access patterns detected",
			"Timestamp sequence valid",
			"Payload checksum matches",
		},
	}

	envelope, err := db.RecordTamperSignal(ctx, envelopeID, tamperSignal)
	if err != nil {
		log.Fatalf("Failed to record tamper signal: %v", err)
	}

	fmt.Printf("✅ Tamper Analysis Complete\n")
	fmt.Printf("   Analyzer: %s v%s\n", tamperSignal.Analyzer, tamperSignal.AnalyzerVersion)
	fmt.Printf("   Score: %.2f / %.2f threshold\n", tamperSignal.Score, tamperSignal.Threshold)
	fmt.Printf("   Status: %s\n", func() string {
		if tamperSignal.Score < tamperSignal.Threshold {
			return "✅ NO TAMPERING DETECTED"
		}
		return "⚠️ POSSIBLE TAMPERING"
	}())
	fmt.Printf("   Findings: %d notes\n", len(tamperSignal.Notes))
	fmt.Printf("   Total Tamper Signals: %d\n", len(envelope.TamperSignals))
}

// legalAuthorityUnlock demonstrates time-lock release
func legalAuthorityUnlock(db *velocity.DB, envelopeID string) {
	ctx := context.Background()

	// In a real scenario, this would require court order validation
	// For demo, we'll simulate immediate approval
	envelope, err := db.ApproveTimeLockUnlock(
		ctx,
		envelopeID,
		"judge-wilson@court.gov",
		"Court Order #CO-2026-5678: Emergency access granted for preliminary hearing",
	)

	// Note: This will fail if time-lock constraints aren't met
	if err != nil {
		fmt.Printf("⚠️  Time-Lock Release Failed: %v\n", err)
		fmt.Printf("   (This is expected if unlock time hasn't been reached)\n")
		return
	}

	fmt.Printf("✅ Time-Lock Released\n")
	fmt.Printf("   Approved By: %s\n", envelope.TimeLockStatus.UnlockApprovedBy)
	fmt.Printf("   Reason: %s\n", envelope.TimeLockStatus.UnlockReason)
	fmt.Printf("   Approved At: %s\n", envelope.TimeLockStatus.UnlockApprovedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Status: PAYLOAD NOW ACCESSIBLE\n")
}

// auditorReview demonstrates full custody chain review
func auditorReview(db *velocity.DB, envelopeID string) {
	ctx := context.Background()

	envelope, err := db.LoadEnvelope(ctx, envelopeID)
	if err != nil {
		log.Fatalf("Failed to load envelope: %v", err)
	}

	fmt.Printf("📋 CHAIN OF CUSTODY AUDIT\n\n")

	// Review custody chain
	fmt.Printf("🔗 Custody Ledger (%d events):\n", len(envelope.CustodyLedger))
	for i, event := range envelope.CustodyLedger {
		fmt.Printf("   [%d] %s\n", i+1, event.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("       Action: %s\n", event.Action)
		fmt.Printf("       Actor: %s\n", event.Actor)
		if event.ActorFingerprint != "" {
			fmt.Printf("       Fingerprint: %s\n", event.ActorFingerprint[:20]+"...")
		}
		if event.Location != "" {
			fmt.Printf("       Location: %s\n", event.Location)
		}
		fmt.Printf("       Hash: %s\n", event.EventHash[:16]+"...")
		if i < len(envelope.CustodyLedger)-1 {
			fmt.Println()
		}
	}

	// Review audit log
	fmt.Printf("\n📝 Audit Log (%d entries):\n", len(envelope.AuditLog))
	for i, entry := range envelope.AuditLog {
		fmt.Printf("   [%d] %s - %s by %s\n",
			i+1,
			entry.Timestamp.Format("15:04:05"),
			entry.Action,
			entry.Actor)
	}

	// Review tamper signals
	if len(envelope.TamperSignals) > 0 {
		fmt.Printf("\n🔍 Tamper Analysis History (%d scans):\n", len(envelope.TamperSignals))
		for i, signal := range envelope.TamperSignals {
			status := "✅ PASS"
			if signal.Score >= signal.Threshold {
				status = "⚠️ ALERT"
			}
			fmt.Printf("   [%d] %s - %s (score: %.2f)\n",
				i+1,
				signal.GeneratedAt.Format("2006-01-02 15:04:05"),
				status,
				signal.Score)
		}
	}

	// Integrity summary
	fmt.Printf("\n🔐 Integrity Status:\n")
	fmt.Printf("   Payload Hash: %s\n", envelope.Integrity.PayloadHash[:24]+"...")
	fmt.Printf("   Ledger Root: %s\n", envelope.Integrity.LedgerRoot[:24]+"...")
	fmt.Printf("   Audit Root: %s\n", envelope.Integrity.AuditRoot[:24]+"...")
	fmt.Printf("   Last Update: %s\n", envelope.Integrity.LastLedgerUpdate.Format("2006-01-02 15:04:05"))
}

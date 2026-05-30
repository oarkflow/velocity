//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/oarkflow/velocity/pkg/compliance"
	"log"
	"os"

	"github.com/oarkflow/velocity"
)

func main() {
	// Clean up
	os.RemoveAll("./compliance-full-demo-data")

	// Create database
	db, err := velocity.New("./compliance-full-demo-data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctm := velocity.NewComplianceTagManager(db)
	ctx := context.Background()

	fmt.Println("=======================================================================")
	fmt.Println("    COMPREHENSIVE COMPLIANCE TAGGING DEMONSTRATION")
	fmt.Println("=======================================================================")

	// ========================================================================
	// SCENARIO 1: TAG A FOLDER WITH COMPLIANCE (HIPAA/PHI)
	// ========================================================================
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println("SCENARIO 1: Folder Tagged with HIPAA Compliance (PHI Data)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")

	// Tag the /healthcare folder with HIPAA compliance
	healthcareTag := &velocity.ComplianceTag{
		Path:          "/healthcare",
		Frameworks:    []compliance.Framework{compliance.FrameworkHIPAA},
		DataClass:     compliance.DataClassRestricted, // PHI is restricted data
		RetentionDays: 2555,                           // 7 years for HIPAA
		EncryptionReq: true,                           // PHI must be encrypted
		AuditLevel:    "high",                         // High audit level
		Owner:         "healthcare-compliance-team",
		CreatedBy:     "compliance-officer",
	}
	if err := ctm.TagPath(ctx, healthcareTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ Tagged /healthcare folder with HIPAA compliance")
	fmt.Printf("  - Frameworks: %v\n", healthcareTag.Frameworks)
	fmt.Printf("  - Data Classification: %v (PHI)\n", healthcareTag.DataClass)
	fmt.Printf("  - Encryption Required: %v\n", healthcareTag.EncryptionReq)
	fmt.Printf("  - Retention: %d days (7 years)\n\n", healthcareTag.RetentionDays)

	// Patient data with PII/PHI
	patientData := map[string]interface{}{
		"patient_id":      "P123456",
		"name":            "John Doe",
		"ssn":             "123-45-6789",
		"date_of_birth":   "1980-05-15",
		"medical_history": "Diabetes Type 2, Hypertension",
		"medications":     []string{"Metformin", "Lisinopril"},
		"last_visit":      "2026-01-20",
		"doctor":          "Dr. Sarah Smith",
	}

	patientJSON, _ := json.Marshal(patientData)
	patientKey := "/healthcare/patients/P123456.json"

	fmt.Println("📋 Attempting to STORE patient data (PHI)...")
	fmt.Printf("   Path: %s\n", patientKey)
	fmt.Printf("   Data: %s\n", string(patientJSON))

	// Validate WRITE operation WITHOUT encryption (should FAIL)
	writeReq := &velocity.ComplianceOperationRequest{
		Path:      patientKey,
		Operation: "write",
		Actor:     "nurse-station-1",
		Encrypted: false, // NOT encrypted
	}
	result, _ := ctm.ValidateOperation(ctx, writeReq)
	fmt.Println("\n❌ VALIDATION RESULT (without encryption):")
	fmt.Printf("   Allowed: %v\n", result.Allowed)
	if !result.Allowed {
		fmt.Printf("   Reason: %s\n", result.Reason)
		for _, rule := range result.ViolatedRules {
			fmt.Printf("   ⚠️  VIOLATION: %s\n", rule)
		}
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Store WITH proper compliance (encrypted)
	fmt.Println("\n📋 Attempting to STORE with ENCRYPTION...")
	writeReq.Encrypted = true
	writeReq.MFAVerified = true
	result, _ = ctm.ValidateOperation(ctx, writeReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		db.Put([]byte(patientKey), patientJSON)
		fmt.Println("   ✓ Patient data stored successfully with encryption")
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate READ operation
	fmt.Println("\n📖 Attempting to READ patient data...")
	readReq := &velocity.ComplianceOperationRequest{
		Path:        patientKey,
		Operation:   "read",
		Actor:       "dr-smith",
		MFAVerified: true,
	}
	result, _ = ctm.ValidateOperation(ctx, readReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		value, _ := db.Get([]byte(patientKey))
		fmt.Printf("   ✓ Retrieved data: %s\n", string(value))
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate UPDATE operation
	fmt.Println("\n✏️  Attempting to UPDATE patient data...")
	updateReq := &velocity.ComplianceOperationRequest{
		Path:        patientKey,
		Operation:   "write",
		Actor:       "dr-smith",
		Encrypted:   true,
		MFAVerified: true,
	}
	result, _ = ctm.ValidateOperation(ctx, updateReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		patientData["last_visit"] = "2026-01-24"
		updatedJSON, _ := json.Marshal(patientData)
		db.Put([]byte(updateReq.Path), updatedJSON)
		fmt.Println("   ✓ Patient data updated successfully")
	}

	// Validate DELETE operation
	fmt.Println("\n🗑️  Attempting to DELETE patient data...")
	deleteReq := &velocity.ComplianceOperationRequest{
		Path:        patientKey,
		Operation:   "delete",
		Actor:       "compliance-officer",
		MFAVerified: true,
		Reason:      "", // No reason provided (should trigger warning)
	}
	result, _ = ctm.ValidateOperation(ctx, deleteReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	for _, action := range result.RequiredActions {
		fmt.Printf("   ⚠️  Action Required: %s\n", action)
	}
	// Provide proper reason
	deleteReq.Reason = "Patient requested data deletion under HIPAA Privacy Rule"
	result, _ = ctm.ValidateOperation(ctx, deleteReq)
	if result.Allowed {
		db.Delete([]byte(patientKey))
		fmt.Println("   ✓ Patient data deleted (with proper reason logged)")
	}

	// ========================================================================
	// SCENARIO 2: TAG A KEY WITH COMPLIANCE (PII - GDPR)
	// ========================================================================
	fmt.Println("\n═══════════════════════════════════════════════════════════════════════")
	fmt.Println("SCENARIO 2: Key-Value Tagged with GDPR Compliance (PII Data)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")

	// Tag a specific key-value with GDPR compliance
	userKeyTag := &velocity.ComplianceTag{
		Path:          "/users/email/john.doe@example.com",
		Frameworks:    []compliance.Framework{compliance.FrameworkGDPR},
		DataClass:     compliance.DataClassConfidential, // PII is confidential
		RetentionDays: 365,                              // 1 year retention
		EncryptionReq: true,                             // Encrypt PII
		AuditLevel:    "high",
		Owner:         "privacy-team",
		CreatedBy:     "data-protection-officer",
	}
	if err := ctm.TagPath(ctx, userKeyTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ Tagged /users/email/john.doe@example.com with GDPR compliance")
	fmt.Printf("  - Frameworks: %v\n", userKeyTag.Frameworks)
	fmt.Printf("  - Data Classification: %v (PII)\n", userKeyTag.DataClass)
	fmt.Printf("  - Retention: %d days\n\n", userKeyTag.RetentionDays)

	// User data with PII
	userData := map[string]interface{}{
		"email":      "john.doe@example.com",
		"full_name":  "John Doe",
		"phone":      "+1-555-0123",
		"address":    "123 Main St, City, State 12345",
		"ip_address": "192.168.1.100",
		"user_agent": "Mozilla/5.0...",
	}
	userJSON, _ := json.Marshal(userData)
	userKey := "/users/email/john.doe@example.com"

	fmt.Println("📋 Attempting to STORE user PII data...")
	fmt.Printf("   Key: %s\n", userKey)
	fmt.Printf("   Data: %s\n", string(userJSON))

	// Validate WRITE without encryption (should FAIL for confidential data)
	userWriteReq := &velocity.ComplianceOperationRequest{
		Path:      userKey,
		Operation: "write",
		Actor:     "app-backend",
		Encrypted: false,
	}
	result, _ = ctm.ValidateOperation(ctx, userWriteReq)
	fmt.Println("\n❌ VALIDATION RESULT (without encryption):")
	fmt.Printf("   Allowed: %v\n", result.Allowed)
	if !result.Allowed {
		for _, rule := range result.ViolatedRules {
			fmt.Printf("   ⚠️  VIOLATION: %s\n", rule)
		}
	}

	// Store WITH encryption
	fmt.Println("\n📋 Attempting to STORE with ENCRYPTION...")
	userWriteReq.Encrypted = true
	result, _ = ctm.ValidateOperation(ctx, userWriteReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		db.Put([]byte(userKey), userJSON)
		fmt.Println("   ✓ User PII stored successfully with encryption")
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate READ
	fmt.Println("\n📖 Attempting to READ user PII...")
	userReadReq := &velocity.ComplianceOperationRequest{
		Path:      userKey,
		Operation: "read",
		Actor:     "app-backend",
	}
	result, _ = ctm.ValidateOperation(ctx, userReadReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		value, _ := db.Get([]byte(userKey))
		fmt.Printf("   ✓ Retrieved data: %s\n", string(value))
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate DELETE (GDPR Right to Erasure)
	fmt.Println("\n🗑️  Attempting to DELETE user data (GDPR Right to Erasure)...")
	userDeleteReq := &velocity.ComplianceOperationRequest{
		Path:      userKey,
		Operation: "delete",
		Actor:     "user-self",
		Reason:    "User exercised GDPR Article 17 right to erasure",
	}
	result, _ = ctm.ValidateOperation(ctx, userDeleteReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		db.Delete([]byte(userKey))
		fmt.Println("   ✓ User data deleted in compliance with GDPR")
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// ========================================================================
	// SCENARIO 3: TAG A FILE WITH COMPLIANCE (PCI DSS - Credit Card Data)
	// ========================================================================
	fmt.Println("\n═══════════════════════════════════════════════════════════════════════")
	fmt.Println("SCENARIO 3: File Tagged with PCI DSS Compliance (Credit Card Data)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")

	// Tag file storage area with PCI DSS compliance
	paymentFileTag := &velocity.ComplianceTag{
		Path:          "/files/payments",
		Frameworks:    []compliance.Framework{compliance.FrameworkPCIDSS},
		DataClass:     compliance.DataClassRestricted, // Cardholder data is restricted
		RetentionDays: 90,                             // PCI DSS retention requirement
		EncryptionReq: true,                           // Must encrypt cardholder data
		AuditLevel:    "high",
		AccessPolicy:  "pci-dss-level-1",
		Owner:         "payment-security-team",
		CreatedBy:     "security-officer",
	}
	if err := ctm.TagPath(ctx, paymentFileTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ Tagged /files/payments with PCI DSS compliance")
	fmt.Printf("  - Frameworks: %v\n", paymentFileTag.Frameworks)
	fmt.Printf("  - Data Classification: %v (Cardholder Data)\n", paymentFileTag.DataClass)
	fmt.Printf("  - Retention: %d days\n", paymentFileTag.RetentionDays)
	fmt.Printf("  - Access Policy: %s\n\n", paymentFileTag.AccessPolicy)

	// Payment transaction data
	paymentData := map[string]interface{}{
		"transaction_id": "TXN-2026-0124-001",
		"card_number":    "4532-****-****-1234", // Masked
		"card_holder":    "John Doe",
		"amount":         99.99,
		"currency":       "USD",
		"timestamp":      "2026-01-24T10:30:00Z",
		"merchant_id":    "MERCH-12345",
	}
	paymentJSON, _ := json.Marshal(paymentData)
	paymentFilePath := "/files/payments/transaction-TXN-2026-0124-001.json"

	fmt.Println("📋 Attempting to UPLOAD payment transaction file...")
	fmt.Printf("   File Path: %s\n", paymentFilePath)
	fmt.Printf("   Data: %s\n", string(paymentJSON))

	// Validate WRITE without MFA (should have requirements)
	fileWriteReq := &velocity.ComplianceOperationRequest{
		Path:        paymentFilePath,
		Operation:   "write",
		Actor:       "payment-processor",
		Encrypted:   true,
		MFAVerified: false, // No MFA
	}
	result, _ = ctm.ValidateOperation(ctx, fileWriteReq)
	fmt.Println("\n⚠️  VALIDATION RESULT (without MFA):")
	fmt.Printf("   Allowed: %v\n", result.Allowed)
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Upload WITH proper compliance (encrypted + MFA)
	fmt.Println("\n📋 Attempting to UPLOAD with proper compliance...")
	fileWriteReq.MFAVerified = true
	result, _ = ctm.ValidateOperation(ctx, fileWriteReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		// Use key-value storage
		err = db.Put([]byte(paymentFilePath), paymentJSON)
		if err != nil {
			fmt.Printf("   ⚠️  Upload error: %v\n", err)
		} else {
			fmt.Println("   ✓ Payment file uploaded successfully")
		}
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate READ
	fmt.Println("\n📖 Attempting to READ payment file...")
	fileReadReq := &velocity.ComplianceOperationRequest{
		Path:        paymentFilePath,
		Operation:   "read",
		Actor:       "auditor",
		MFAVerified: true,
	}
	result, _ = ctm.ValidateOperation(ctx, fileReadReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		data, err := db.Get([]byte(paymentFilePath))
		if err != nil {
			fmt.Printf("   ⚠️  Read error: %v\n", err)
		} else {
			fmt.Printf("   ✓ Retrieved file: %s\n", string(data))
		}
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// Validate DELETE
	fmt.Println("\n🗑️  Attempting to DELETE payment file (retention expired)...")
	fileDeleteReq := &velocity.ComplianceOperationRequest{
		Path:        paymentFilePath,
		Operation:   "delete",
		Actor:       "system-cleanup",
		DataAge:     95, // Exceeds 90-day retention
		MFAVerified: true,
		Reason:      "Automated deletion after retention period",
	}
	result, _ = ctm.ValidateOperation(ctx, fileDeleteReq)
	fmt.Printf("✅ VALIDATION RESULT: Allowed=%v\n", result.Allowed)
	if result.Allowed {
		db.Delete([]byte(paymentFilePath))
		fmt.Println("   ✓ Payment file deleted after retention period")
	}
	for _, action := range result.RequiredActions {
		fmt.Printf("   ➜ Action Required: %s\n", action)
	}

	// ========================================================================
	// SUMMARY: KEY INSIGHTS
	// ========================================================================
	fmt.Println("\n═══════════════════════════════════════════════════════════════════════")
	fmt.Println("                            KEY INSIGHTS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")

	fmt.Println("1. FOLDER TAGGING (HIPAA/PHI):")
	fmt.Println("   • Tags apply to ALL data under that folder path")
	fmt.Println("   • Validates EVERY operation (store, get, update, delete)")
	fmt.Println("   • Enforces: encryption, MFA, audit logging, retention")
	fmt.Println("   • Prevents non-compliant operations (returns Allowed=false)")
	fmt.Println("")

	fmt.Println("2. KEY TAGGING (GDPR/PII):")
	fmt.Println("   • Tags apply to specific key-value pairs")
	fmt.Println("   • Validates: consent, encryption, retention, right to erasure")
	fmt.Println("   • Tracks actions required for compliance")
	fmt.Println("   • Supports GDPR Article 17 (right to be forgotten)")
	fmt.Println("")

	fmt.Println("3. FILE TAGGING (PCI DSS/Cardholder Data):")
	fmt.Println("   • Tags apply to file storage paths")
	fmt.Println("   • Enforces: strong encryption, MFA, access policies")
	fmt.Println("   • Validates retention periods for cardholder data")
	fmt.Println("   • Integrates with object storage operations")
	fmt.Println("")

	fmt.Println("WHAT HAPPENS DURING OPERATIONS:")
	fmt.Println("   ✓ ValidateOperation() checks compliance BEFORE executing")
	fmt.Println("   ✓ Returns Allowed=true/false based on compliance rules")
	fmt.Println("   ✓ Lists ViolatedRules if operation is not compliant")
	fmt.Println("   ✓ Provides RequiredActions for compliance (logging, consent, etc.)")
	fmt.Println("   ✓ Enforces encryption, MFA, retention, and audit requirements")
	fmt.Println("")

	fmt.Println("INHERITANCE:")
	fmt.Println("   • Child paths inherit parent folder tags")
	fmt.Println("   • /healthcare/patients inherits /healthcare compliance")
	fmt.Println("   • More specific tags override parent settings")
	fmt.Println("")

	fmt.Println("═══════════════════════════════════════════════════════════════════════")
}

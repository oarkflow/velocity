package velocity

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestComplianceTagManager_TagPath(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Test tagging a folder with GDPR
	tag := &ComplianceTag{
		Path:          "/folderA",
		Frameworks:    []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		DataClass:     DataClassConfidential,
		Owner:         "legal-team",
		Custodian:     "data-custodian-01",
		RetentionDays: 730, // 2 years
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "admin",
	}

	err = ctm.TagPath(ctx, tag)
	if err != nil {
		t.Fatalf("Failed to tag path: %v", err)
	}

	// Verify tag was stored
	retrievedTag := ctm.GetTag("/folderA")
	if retrievedTag == nil {
		t.Fatal("Tag not found")
	}

	if len(retrievedTag.Frameworks) != 2 {
		t.Errorf("Expected 2 frameworks, got %d", len(retrievedTag.Frameworks))
	}

	if retrievedTag.EncryptionReq != true {
		t.Error("Encryption requirement not set")
	}
}

func TestComplianceTagManager_Inheritance(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag parent folder
	parentTag := &ComplianceTag{
		Path:          "/folderA",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassRestricted,
		EncryptionReq: true,
		CreatedBy:     "admin",
	}

	err = ctm.TagPath(ctx, parentTag)
	if err != nil {
		t.Fatalf("Failed to tag parent: %v", err)
	}

	// Check child inherits parent's compliance
	childPath := "/folderA/subfolder/file.txt"
	childTag := ctm.GetTag(childPath)

	if childTag == nil {
		t.Fatal("Child should inherit parent tag")
	}

	if len(childTag.Frameworks) != 1 || childTag.Frameworks[0] != FrameworkGDPR {
		t.Error("Child did not inherit GDPR framework")
	}

	if childTag.DataClass != DataClassRestricted {
		t.Error("Child did not inherit data classification")
	}

	if !childTag.EncryptionReq {
		t.Error("Child did not inherit encryption requirement")
	}
}

func TestComplianceTagManager_ValidateOperation_GDPR(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag with GDPR
	tag := &ComplianceTag{
		Path:          "/gdpr-data",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassConfidential,
		EncryptionReq: true,
		CreatedBy:     "admin",
	}
	ctm.TagPath(ctx, tag)

	// Test write without encryption (should fail)
	req := &ComplianceOperationRequest{
		Path:      "/gdpr-data/user-records.json",
		Operation: "write",
		Actor:     "user-01",
		Encrypted: false,
		Timestamp: time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if result.Allowed {
		t.Error("Expected write without encryption to be rejected for GDPR data")
	}

	if len(result.ViolatedRules) == 0 {
		t.Error("Expected violated rules to be reported")
	}

	// Test write with encryption (should pass)
	req.Encrypted = true
	result, err = ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Expected write with encryption to be allowed, reason: %v", result.ViolatedRules)
	}
}

func TestComplianceTagManager_ValidateOperation_HIPAA(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag with HIPAA
	tag := &ComplianceTag{
		Path:       "/phi-records",
		Frameworks: []ComplianceFramework{FrameworkHIPAA},
		DataClass:  DataClassRestricted,
		CreatedBy:  "compliance-officer",
	}
	ctm.TagPath(ctx, tag)

	// Test write without encryption (should fail HIPAA Security Rule)
	req := &ComplianceOperationRequest{
		Path:      "/phi-records/patient-123.json",
		Operation: "write",
		Actor:     "doctor-01",
		Encrypted: false,
		Timestamp: time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if result.Allowed {
		t.Error("Expected PHI write without encryption to be rejected")
	}

	// Check for HIPAA-specific violations
	foundHIPAA := false
	for _, rule := range result.ViolatedRules {
		if strings.Contains(rule, "HIPAA") {
			foundHIPAA = true
			break
		}
	}
	if !foundHIPAA {
		t.Error("Expected HIPAA violation to be reported")
	}

	// Test read (should require audit logging)
	req.Operation = "read"
	req.Encrypted = true
	result, err = ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	foundAudit := false
	for _, action := range result.RequiredActions {
		if strings.Contains(action, "HIPAA audit") {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Error("Expected HIPAA audit requirement for PHI read")
	}
}

func TestComplianceTagManager_ValidateOperation_PCIDSS(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag with PCI DSS
	tag := &ComplianceTag{
		Path:          "/cardholder-data",
		Frameworks:    []ComplianceFramework{FrameworkPCIDSS},
		DataClass:     DataClassRestricted,
		RetentionDays: 365,
		CreatedBy:     "security-officer",
	}
	ctm.TagPath(ctx, tag)

	// Test write without MFA (should fail PCI DSS 8.3)
	req := &ComplianceOperationRequest{
		Path:        "/cardholder-data/transactions.db",
		Operation:   "write",
		Actor:       "payment-processor",
		Encrypted:   true,
		MFAVerified: false,
		Timestamp:   time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if result.Allowed {
		t.Error("Expected cardholder data write without MFA to be rejected")
	}

	// Check for PCI DSS MFA requirement
	foundMFA := false
	for _, rule := range result.ViolatedRules {
		if strings.Contains(rule, "MFA") && strings.Contains(rule, "PCI") {
			foundMFA = true
			break
		}
	}
	if !foundMFA {
		t.Error("Expected PCI DSS MFA violation")
	}

	// Test with MFA (should pass)
	req.MFAVerified = true
	result, err = ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Expected write with MFA to be allowed, violations: %v", result.ViolatedRules)
	}
}

func TestComplianceTagManager_ValidateOperation_FIPS(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag with FIPS
	tag := &ComplianceTag{
		Path:       "/classified-data",
		Frameworks: []ComplianceFramework{FrameworkFIPS},
		DataClass:  DataClassRestricted,
		CreatedBy:  "security-admin",
	}
	ctm.TagPath(ctx, tag)

	// Test write with non-approved algorithm (should fail)
	req := &ComplianceOperationRequest{
		Path:            "/classified-data/secret.bin",
		Operation:       "write",
		Actor:           "operator-01",
		Encrypted:       true,
		CryptoAlgorithm: "DES", // Not FIPS approved
		Timestamp:       time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if result.Allowed {
		t.Error("Expected write with non-FIPS algorithm to be rejected")
	}

	// Test write with approved algorithm (should pass)
	req.CryptoAlgorithm = "AES-256-GCM"
	result, err = ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Expected write with FIPS-approved algorithm to be allowed, violations: %v", result.ViolatedRules)
	}
}

func TestComplianceTagManager_MultiFramework(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag with multiple frameworks
	tag := &ComplianceTag{
		Path: "/healthcare-payments",
		Frameworks: []ComplianceFramework{
			FrameworkHIPAA,
			FrameworkPCIDSS,
			FrameworkSOC2,
		},
		DataClass:     DataClassRestricted,
		EncryptionReq: true,
		RetentionDays: 2555, // 7 years
		CreatedBy:     "compliance-team",
	}
	ctm.TagPath(ctx, tag)

	// Test operation must satisfy ALL frameworks
	req := &ComplianceOperationRequest{
		Path:            "/healthcare-payments/billing.db",
		Operation:       "write",
		Actor:           "billing-system",
		Encrypted:       true,
		MFAVerified:     true,
		CryptoAlgorithm: "AES-256-GCM",
		Timestamp:       time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should require actions from multiple frameworks
	if len(result.RequiredActions) < 3 {
		t.Errorf("Expected required actions from multiple frameworks, got %d actions", len(result.RequiredActions))
	}

	// Check that actions mention different frameworks
	frameworks := make(map[string]bool)
	for _, action := range result.RequiredActions {
		if strings.Contains(action, "HIPAA") {
			frameworks["HIPAA"] = true
		}
		if strings.Contains(action, "PCI") {
			frameworks["PCI"] = true
		}
		if strings.Contains(action, "SOC2") {
			frameworks["SOC2"] = true
		}
	}

	if len(frameworks) < 2 {
		t.Error("Expected required actions from multiple frameworks")
	}
}

func TestComplianceTagManager_RemoveTag(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag a path
	tag := &ComplianceTag{
		Path:       "/temporary-data",
		Frameworks: []ComplianceFramework{FrameworkGDPR},
		CreatedBy:  "admin",
	}
	ctm.TagPath(ctx, tag)

	// Verify it exists
	if ctm.GetTag("/temporary-data") == nil {
		t.Fatal("Tag not found after creation")
	}

	// Remove tag
	err = ctm.RemoveTag(ctx, "/temporary-data")
	if err != nil {
		t.Fatalf("Failed to remove tag: %v", err)
	}

	// Verify it's gone
	if ctm.GetTag("/temporary-data") != nil {
		t.Error("Tag still exists after removal")
	}
}

func TestComplianceTagManager_ListByFramework(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Tag multiple paths with different frameworks
	tags := []*ComplianceTag{
		{Path: "/gdpr-data-1", Frameworks: []ComplianceFramework{FrameworkGDPR}, CreatedBy: "admin"},
		{Path: "/gdpr-data-2", Frameworks: []ComplianceFramework{FrameworkGDPR}, CreatedBy: "admin"},
		{Path: "/hipaa-data", Frameworks: []ComplianceFramework{FrameworkHIPAA}, CreatedBy: "admin"},
		{Path: "/mixed-data", Frameworks: []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA}, CreatedBy: "admin"},
	}

	for _, tag := range tags {
		ctm.TagPath(ctx, tag)
	}

	// List GDPR tags
	gdprTags := ctm.ListTagsByFramework(FrameworkGDPR)
	if len(gdprTags) != 3 {
		t.Errorf("Expected 3 GDPR tags, got %d", len(gdprTags))
	}

	// List HIPAA tags
	hipaaTags := ctm.ListTagsByFramework(FrameworkHIPAA)
	if len(hipaaTags) != 2 {
		t.Errorf("Expected 2 HIPAA tags, got %d", len(hipaaTags))
	}
}

func TestComplianceTagManager_UpdateTag(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Create initial tag
	tag := &ComplianceTag{
		Path:          "/evolving-data",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		RetentionDays: 365,
		CreatedBy:     "admin",
	}
	ctm.TagPath(ctx, tag)

	// Get the created tag to obtain its TagID
	createdTag := ctm.GetTag("/evolving-data")
	if createdTag == nil || createdTag.TagID == "" {
		t.Fatal("Failed to get created tag or TagID is empty")
	}

	// Update tag by TagID
	err = ctm.UpdateTag(ctx, createdTag.TagID, func(t *ComplianceTag) error {
		t.Frameworks = append(t.Frameworks, FrameworkHIPAA)
		t.RetentionDays = 730
		t.EncryptionReq = true
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to update tag: %v", err)
	}

	// Verify updates
	updated := ctm.GetTag("/evolving-data")
	if len(updated.Frameworks) != 2 {
		t.Errorf("Expected 2 frameworks after update, got %d", len(updated.Frameworks))
	}
	if updated.RetentionDays != 730 {
		t.Errorf("Expected retention days 730, got %d", updated.RetentionDays)
	}
	if !updated.EncryptionReq {
		t.Error("Expected encryption requirement to be set")
	}
}

func TestComplianceTagManager_NoTag(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Test operation on untagged path (should be allowed)
	req := &ComplianceOperationRequest{
		Path:      "/untagged-data/file.txt",
		Operation: "write",
		Actor:     "user-01",
		Encrypted: false,
		Timestamp: time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected operation on untagged path to be allowed")
	}

	if result.Reason != "no compliance tags applied" {
		t.Errorf("Expected 'no compliance tags' reason, got: %s", result.Reason)
	}
}

func TestComplianceTagManager_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Create and tag
	db1, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	ctm1 := NewComplianceTagManager(db1)
	tag := &ComplianceTag{
		Path:       "/persistent-data",
		Frameworks: []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		DataClass:  DataClassRestricted,
		CreatedBy:  "admin",
	}
	err = ctm1.TagPath(context.Background(), tag)
	if err != nil {
		t.Fatalf("Failed to tag path: %v", err)
	}

	// Close will flush memtable automatically
	if err := db1.Close(); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	// Give filesystem time to sync
	time.Sleep(100 * time.Millisecond)

	// Reopen and verify persistence
	db2, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer db2.Close()

	// Load tags through manager (which reads from database)
	ctm2 := NewComplianceTagManager(db2)

	// Retrieve tag using GetTag (which loads from database)
	retrieved := ctm2.GetTag("/persistent-data")
	if retrieved == nil {
		t.Fatal("Tag not persisted across database reopening")
	}

	if len(retrieved.Frameworks) != 2 {
		t.Errorf("Expected 2 frameworks after reload, got %d", len(retrieved.Frameworks))
	}

	if retrieved.DataClass != DataClassRestricted {
		t.Error("Data classification not persisted")
	}

	t.Log("✓ Compliance tag successfully persisted and retrieved after database reopen")
}

// Helper function in strings package is used directly

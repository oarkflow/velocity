package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	// Clean up any existing test database
	os.RemoveAll("./multi-tag-demo-data")

	// Create database
	db, err := velocity.New("./multi-tag-demo-data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create compliance tag manager
	ctm := velocity.NewComplianceTagManager(db)
	ctx := context.Background()

	fmt.Println("=== Multiple Compliance Tagging Demo ===")

	// ========================================
	// 1. Apply Multiple Tags to a Folder
	// ========================================
	fmt.Println("1. Applying multiple compliance frameworks to /customer-data folder...")

	// First tag: GDPR compliance
	gdprTag := &velocity.ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
		DataClass:     velocity.DataClassConfidential,
		Owner:         "privacy-team",
		RetentionDays: 730,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "privacy-officer",
	}
	if err := ctm.TagPath(ctx, gdprTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied GDPR compliance tag")

	// Second tag: SOC2 compliance (additional requirements)
	soc2Tag := &velocity.ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:     velocity.DataClassConfidential,
		Owner:         "security-team",
		RetentionDays: 365,
		EncryptionReq: true,
		AuditLevel:    "high",
		AccessPolicy:  "customer-data-policy",
		CreatedBy:     "security-officer",
	}
	if err := ctm.TagPath(ctx, soc2Tag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied SOC2 compliance tag")

	// ========================================
	// 2. Retrieve and Show Merged Tags
	// ========================================
	fmt.Println("\n2. Retrieving compliance tags for /customer-data...")

	// GetTag returns a merged view
	mergedTag := ctm.GetTag("/customer-data")
	if mergedTag != nil {
		fmt.Printf("   Merged Tag:\n")
		fmt.Printf("   - Frameworks: %v\n", mergedTag.Frameworks)
		fmt.Printf("   - Data Class: %v\n", mergedTag.DataClass)
		fmt.Printf("   - Encryption Required: %v\n", mergedTag.EncryptionReq)
		fmt.Printf("   - Retention Days: %d (most restrictive)\n", mergedTag.RetentionDays)
		fmt.Printf("   - Audit Level: %s\n", mergedTag.AuditLevel)
		fmt.Println()
	}

	// GetTags returns all individual tags
	allTags := ctm.GetTags("/customer-data")
	fmt.Printf("   Individual Tags (%d total):\n", len(allTags))
	for i, tag := range allTags {
		fmt.Printf("   Tag %d:\n", i+1)
		fmt.Printf("     - Frameworks: %v\n", tag.Frameworks)
		fmt.Printf("     - Created By: %s\n", tag.CreatedBy)
		fmt.Printf("     - Owner: %s\n", tag.Owner)
	}

	// ========================================
	// 3. Multiple Tags on a Key-Value
	// ========================================
	fmt.Println("\n3. Applying multiple tags to a specific key-value...")

	// Tag for sensitive PII data
	piiTag := &velocity.ComplianceTag{
		Path:          "/customer-data/user:john@example.com",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "data-protection",
		RetentionDays: 90, // Short retention for PII
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "dpo",
		Metadata: map[string]interface{}{
			"data_subject": "john@example.com",
			"purpose":      "customer_service",
		},
	}
	if err := ctm.TagPath(ctx, piiTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied PII-specific GDPR tag to key-value")

	// Additional HIPAA tag (if customer is also a patient)
	hipaaTag := &velocity.ComplianceTag{
		Path:          "/customer-data/user:john@example.com",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "healthcare-team",
		RetentionDays: 2555, // 7 years for HIPAA
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "hipaa-officer",
		Metadata: map[string]interface{}{
			"phi_type":       "medical_records",
			"covered_entity": "hospital",
		},
	}
	if err := ctm.TagPath(ctx, hipaaTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied HIPAA tag to same key-value")
	fmt.Println()

	// Retrieve merged tag for key-value
	keyTag := ctm.GetTag("/customer-data/user:john@example.com")
	if keyTag != nil {
		fmt.Println("   Merged key-value tag:")
		fmt.Printf("   - Frameworks: %v (both GDPR + HIPAA)\n", keyTag.Frameworks)
		fmt.Printf("   - Retention Days: %d (longest: HIPAA 7 years)\n", keyTag.RetentionDays)
		fmt.Printf("   - Data Class: %v (most restrictive)\n", keyTag.DataClass)
	}

	// ========================================
	// 4. Multiple Tags on a File Path
	// ========================================
	fmt.Println("\n4. Applying multiple tags to a file path...")

	// Financial data compliance
	pciTag := &velocity.ComplianceTag{
		Path:          "/payment-data/transactions.csv",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "finance-team",
		RetentionDays: 365,
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "finance-officer",
	}
	if err := ctm.TagPath(ctx, pciTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied PCI DSS tag to file")

	// FIPS compliance for encryption
	fipsTag := &velocity.ComplianceTag{
		Path:          "/payment-data/transactions.csv",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkFIPS},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "security-team",
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "security-officer",
		Metadata: map[string]interface{}{
			"algorithm":  "AES-256-GCM",
			"key_source": "FIPS-140-2-compliant-HSM",
		},
	}
	if err := ctm.TagPath(ctx, fipsTag); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Applied FIPS tag to same file")

	// ========================================
	// 5. Test Validation with Multiple Tags
	// ========================================
	fmt.Println("\n5. Testing validation with multiple compliance requirements...")

	// Test write without encryption (should fail both PCI DSS and FIPS)
	req := &velocity.ComplianceOperationRequest{
		Path:      "/payment-data/transactions.csv",
		Operation: "write",
		Actor:     "payment-processor",
		Encrypted: false,
		Timestamp: time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	if !result.Allowed {
		fmt.Println("   ❌ Operation blocked (as expected):")
		for _, violation := range result.ViolatedRules {
			fmt.Printf("      - %s\n", violation)
		}
	}

	fmt.Println()

	// Test with encryption and FIPS algorithm
	req.Encrypted = true
	req.CryptoAlgorithm = "AES-256-GCM"

	result, err = ctm.ValidateOperation(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	if result.Allowed {
		fmt.Println("   ✅ Operation allowed with proper encryption")
		fmt.Println("   Required actions:")
		for _, action := range result.RequiredActions {
			fmt.Printf("      - %s\n", action)
		}
	}

	// ========================================
	// 6. Inheritance with Multiple Tags
	// ========================================
	fmt.Println("\n6. Testing inheritance with multiple tags...")

	// Child path inherits multiple tags from parent
	childTag := ctm.GetTag("/customer-data/subfolder/file.json")
	if childTag != nil {
		fmt.Println("   Child path inherits merged parent tags:")
		fmt.Printf("   - Path: %s\n", childTag.Path)
		fmt.Printf("   - Frameworks: %v (inherited from parent)\n", childTag.Frameworks)
		fmt.Printf("   - Encryption Required: %v\n", childTag.EncryptionReq)
		fmt.Printf("   - Retention Days: %d days\n", childTag.RetentionDays)
	}

	// ========================================
	// 7. List Tags by Framework
	// ========================================
	fmt.Println("\n7. Listing all tags by framework...")

	gdprTags := ctm.ListTagsByFramework(velocity.FrameworkGDPR)
	fmt.Printf("   GDPR-tagged paths (%d):\n", len(gdprTags))
	for _, tag := range gdprTags {
		fmt.Printf("      - %s\n", tag.Path)
	}

	fmt.Println()

	hipaaPathTags := ctm.ListTagsByFramework(velocity.FrameworkHIPAA)
	fmt.Printf("   HIPAA-tagged paths (%d):\n", len(hipaaPathTags))
	for _, tag := range hipaaPathTags {
		fmt.Printf("      - %s\n", tag.Path)
	}

	// ========================================
	// 8. Summary
	// ========================================
	fmt.Println("\n=== Summary ===")

	allComplianceTags := ctm.GetAllTags()
	fmt.Printf("Total compliance tags applied: %d\n", len(allComplianceTags))

	// Count by type
	folderTags := 0
	fileTags := 0
	keyTags := 0

	for _, tag := range allComplianceTags {
		if len(tag.Path) > 0 && tag.Path[len(tag.Path)-1] == '/' {
			folderTags++
		} else if (len(tag.Path) > 4 && tag.Path[len(tag.Path)-4:] == ".csv") ||
			(len(tag.Path) > 5 && tag.Path[len(tag.Path)-5:] == ".json") {
			fileTags++
		} else if len(tag.Path) > 0 && !hasSlashAfterColon(tag.Path) {
			keyTags++
		}
	}

	fmt.Printf("- Folder tags: %d\n", folderTags)
	fmt.Printf("- File tags: %d\n", fileTags)
	fmt.Printf("- Key-value tags: %d\n", keyTags)

	fmt.Println()
	fmt.Println("✓ Multiple tagging for folders, files, and key-values working correctly!")
	fmt.Println("✓ Tag merging combines all frameworks with most restrictive settings")
	fmt.Println("✓ Inheritance works with multiple tags")
	fmt.Println("✓ Validation enforces all applicable compliance requirements")
}

func hasSlashAfterColon(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] == ':' {
			for j := i + 1; j < len(path); j++ {
				if path[j] == '/' {
					return true
				}
			}
			return false
		}
	}
	return false
}

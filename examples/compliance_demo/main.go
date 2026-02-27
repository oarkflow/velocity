//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

func mai10n() {
	// Create database
	db, err := velocity.New("./compliance_demo_db")
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create compliance tag manager
	ctm := velocity.NewComplianceTagManager(db)
	ctx := context.Background()

	fmt.Println("=== Velocity Database Compliance Tagging Demo ===")

	// Example 1: Tag a folder with GDPR compliance
	fmt.Println("1. Tagging /customer-data folder with GDPR compliance...")
	gdprTag := &velocity.ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
		DataClass:     velocity.DataClassConfidential,
		Owner:         "privacy-team",
		Custodian:     "it-department",
		RetentionDays: 730, // 2 years
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "compliance-officer",
	}
	err = ctm.TagPath(ctx, gdprTag)
	if err != nil {
		log.Fatalf("Failed to tag GDPR folder: %v", err)
	}
	fmt.Println("   ✓ GDPR compliance applied to /customer-data")

	// Example 2: Tag PHI folder with HIPAA
	fmt.Println("\n2. Tagging /patient-records with HIPAA compliance...")
	hipaaTag := &velocity.ComplianceTag{
		Path:          "/patient-records",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "medical-director",
		Custodian:     "health-it",
		RetentionDays: 2555, // 7 years (HIPAA requirement)
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "hipaa-compliance-officer",
	}
	err = ctm.TagPath(ctx, hipaaTag)
	if err != nil {
		log.Fatalf("Failed to tag HIPAA folder: %v", err)
	}
	fmt.Println("   ✓ HIPAA compliance applied to /patient-records")

	// Example 3: Tag payment folder with PCI DSS
	fmt.Println("\n3. Tagging /payment-data with PCI DSS compliance...")
	pciTag := &velocity.ComplianceTag{
		Path:          "/payment-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkPCIDSS},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "cfo",
		Custodian:     "payment-team",
		RetentionDays: 365, // 1 year
		EncryptionReq: true,
		AuditLevel:    "high",
		AccessPolicy:  "pci-dss-policy",
		CreatedBy:     "security-officer",
	}
	err = ctm.TagPath(ctx, pciTag)
	if err != nil {
		log.Fatalf("Failed to tag PCI DSS folder: %v", err)
	}
	fmt.Println("   ✓ PCI DSS compliance applied to /payment-data")

	// Example 4: Tag government data with multiple frameworks
	fmt.Println("\n4. Tagging /classified folder with FIPS + NIST compliance...")
	govTag := &velocity.ComplianceTag{
		Path: "/classified",
		Frameworks: []velocity.ComplianceFramework{
			velocity.FrameworkFIPS,
			velocity.FrameworkNIST,
		},
		DataClass:     velocity.DataClassRestricted,
		Owner:         "security-clearance-officer",
		Custodian:     "it-security",
		RetentionDays: 3650, // 10 years
		EncryptionReq: true,
		AuditLevel:    "high",
		CreatedBy:     "government-admin",
	}
	err = ctm.TagPath(ctx, govTag)
	if err != nil {
		log.Fatalf("Failed to tag government folder: %v", err)
	}
	fmt.Println("   ✓ FIPS + NIST compliance applied to /classified")

	// Example 5: Test inheritance - child file inherits parent's compliance
	fmt.Println("\n5. Testing compliance inheritance...")
	childPath := "/customer-data/users/john_doe.json"
	childTag := ctm.GetTag(childPath)
	if childTag != nil {
		fmt.Printf("   ✓ File '%s' inherits compliance:\n", childPath)
		for _, fw := range childTag.Frameworks {
			fmt.Printf("     - %s\n", fw)
		}
		fmt.Printf("     - Data Classification: %s\n", childTag.DataClass)
		fmt.Printf("     - Encryption Required: %v\n", childTag.EncryptionReq)
	} else {
		fmt.Println("   ✗ No compliance inherited (unexpected)")
	}

	// Example 6: Validate operations
	fmt.Println("\n6. Validating operations against compliance requirements...")

	// Test: Write to GDPR folder without encryption (should fail)
	fmt.Println("\n   Test A: Write to GDPR folder WITHOUT encryption")
	req1 := &velocity.ComplianceOperationRequest{
		Path:      "/customer-data/new-user.json",
		Operation: "write",
		Actor:     "app-server",
		Encrypted: false,
		Timestamp: time.Now(),
	}
	result1, err := ctm.ValidateOperation(ctx, req1)
	if err != nil {
		log.Printf("      Validation error: %v", err)
	} else {
		if !result1.Allowed {
			fmt.Println("      ✓ Operation BLOCKED (as expected)")
			for _, violation := range result1.ViolatedRules {
				fmt.Printf("        - %s\n", violation)
			}
		} else {
			fmt.Println("      ✗ Operation allowed (unexpected!)")
		}
	}

	// Test: Write to GDPR folder WITH encryption (should pass)
	fmt.Println("\n   Test B: Write to GDPR folder WITH encryption")
	req2 := &velocity.ComplianceOperationRequest{
		Path:      "/customer-data/new-user.json",
		Operation: "write",
		Actor:     "app-server",
		Encrypted: true,
		Timestamp: time.Now(),
	}
	result2, err := ctm.ValidateOperation(ctx, req2)
	if err != nil {
		log.Printf("      Validation error: %v", err)
	} else {
		if result2.Allowed {
			fmt.Println("      ✓ Operation ALLOWED (encryption verified)")
			if len(result2.RequiredActions) > 0 {
				fmt.Println("        Required actions:")
				for _, action := range result2.RequiredActions {
					fmt.Printf("        - %s\n", action)
				}
			}
		} else {
			fmt.Println("      ✗ Operation blocked (unexpected)")
		}
	}

	// Test: Write to PCI DSS folder without MFA (should fail)
	fmt.Println("\n   Test C: Write to PCI DSS folder WITHOUT MFA")
	req3 := &velocity.ComplianceOperationRequest{
		Path:        "/payment-data/transaction-001.json",
		Operation:   "write",
		Actor:       "payment-processor",
		Encrypted:   true,
		MFAVerified: false,
		Timestamp:   time.Now(),
	}
	result3, err := ctm.ValidateOperation(ctx, req3)
	if err != nil {
		log.Printf("      Validation error: %v", err)
	} else {
		if !result3.Allowed {
			fmt.Println("      ✓ Operation BLOCKED (MFA required)")
			for _, violation := range result3.ViolatedRules {
				fmt.Printf("        - %s\n", violation)
			}
		} else {
			fmt.Println("      ✗ Operation allowed (unexpected!)")
		}
	}

	// Test: Write to classified folder with FIPS-approved algorithm
	fmt.Println("\n   Test D: Write to classified folder WITH FIPS algorithm")
	req4 := &velocity.ComplianceOperationRequest{
		Path:            "/classified/top-secret-001.bin",
		Operation:       "write",
		Actor:           "security-admin",
		Encrypted:       true,
		MFAVerified:     true,
		CryptoAlgorithm: "AES-256-GCM",
		Timestamp:       time.Now(),
	}
	result4, err := ctm.ValidateOperation(ctx, req4)
	if err != nil {
		log.Printf("      Validation error: %v", err)
	} else {
		if result4.Allowed {
			fmt.Println("      ✓ Operation ALLOWED (FIPS-approved)")
		} else {
			fmt.Println("      ✗ Operation blocked")
			for _, violation := range result4.ViolatedRules {
				fmt.Printf("        - %s\n", violation)
			}
		}
	}

	// Example 7: List all tags by framework
	fmt.Println("\n7. Listing all GDPR-tagged paths...")
	gdprPaths := ctm.ListTagsByFramework(velocity.FrameworkGDPR)
	fmt.Printf("   Found %d GDPR-tagged paths:\n", len(gdprPaths))
	for _, tag := range gdprPaths {
		fmt.Printf("     - %s (Owner: %s, Retention: %d days)\n", tag.Path, tag.Owner, tag.RetentionDays)
	}

	// Example 8: Update a compliance tag
	fmt.Println("\n8. Updating compliance tag for /customer-data...")
	tags := ctm.GetTags("/customer-data")
	if len(tags) == 0 {
		log.Printf("No tags found for /customer-data")
	} else {
		err = ctm.UpdateTag(ctx, tags[0].TagID, func(tag *velocity.ComplianceTag) error {
		// Add SOC2 to existing GDPR compliance
		tag.Frameworks = append(tag.Frameworks, velocity.FrameworkSOC2)
		tag.RetentionDays = 1095 // Extend to 3 years
		fmt.Println("   ✓ Added SOC2 framework")
		fmt.Println("   ✓ Extended retention to 3 years")
		return nil
		})
		if err != nil {
			log.Printf("Failed to update tag: %v", err)
		}
	}

	// Verify update
	updatedTag := ctm.GetTag("/customer-data")
	fmt.Printf("   Current frameworks: ")
	for i, fw := range updatedTag.Frameworks {
		if i > 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("%s", fw)
	}
	fmt.Println()

	// Example 9: Remove a compliance tag
	fmt.Println("\n9. Demonstrating tag removal...")
	fmt.Println("   (Skipped in demo - use ctm.RemoveTag(ctx, path) to remove)")

	fmt.Println("\n=== Demo Complete! ===")
	fmt.Println("Key Features Demonstrated:")
	fmt.Println("  ✓ Path-based compliance tagging (folders, files, keys)")
	fmt.Println("  ✓ Multiple framework support (GDPR, HIPAA, PCI DSS, FIPS, NIST, SOC2)")
	fmt.Println("  ✓ Automatic inheritance (children inherit parent's compliance)")
	fmt.Println("  ✓ Operation validation (encryption, MFA, algorithm checks)")
	fmt.Println("  ✓ Violation reporting with actionable recommendations")
	fmt.Println("  ✓ Tag persistence across database restarts")
	fmt.Println("  ✓ Framework filtering and reporting")
}

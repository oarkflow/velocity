//go:build velocity_examples
// +build velocity_examples

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity"
)

func main() {
	// Clean up
	os.RemoveAll("./update-demo-data")

	// Create database
	db, err := velocity.New("./update-demo-data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctm := velocity.NewComplianceTagManager(db)
	ctx := context.Background()

	fmt.Println("=== Compliance Tag Update Methods Demo ===")

	// Apply multiple tags to same path
	fmt.Println("1. Creating multiple tags for /customer-data...")

	gdprTag := &velocity.ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
		DataClass:     velocity.DataClassConfidential,
		RetentionDays: 365,
		Owner:         "privacy-team",
		CreatedBy:     "privacy-officer",
	}
	ctm.TagPath(ctx, gdprTag)
	fmt.Printf("   ✓ Created GDPR tag (ID: %s)\n", gdprTag.TagID)

	soc2Tag := &velocity.ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:     velocity.DataClassConfidential,
		RetentionDays: 730,
		Owner:         "security-team",
		CreatedBy:     "security-officer",
	}
	ctm.TagPath(ctx, soc2Tag)
	fmt.Printf("   ✓ Created SOC2 tag (ID: %s)\n\n", soc2Tag.TagID)

	// Show all tags
	allTags := ctm.GetTags("/customer-data")
	fmt.Printf("Current tags for /customer-data: %d\n", len(allTags))
	for i, tag := range allTags {
		fmt.Printf("   Tag %d: %v, Retention: %d days, Owner: %s\n",
			i+1, tag.Frameworks, tag.RetentionDays, tag.Owner)
	}
	fmt.Println()

	// Method 1: Update by TagID (most specific)
	fmt.Println("2. Update specific tag by TagID...")
	fmt.Printf("   Updating GDPR tag (ID: %s)\n", gdprTag.TagID)

	err = ctm.UpdateTag(ctx, gdprTag.TagID, func(tag *velocity.ComplianceTag) error {
		tag.RetentionDays = 500
		tag.EncryptionReq = true
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	updated := ctm.GetTag("/customer-data") // Gets merged view
	fmt.Printf("   ✓ Updated! Merged view now shows: Retention=%d days, Encryption=%v\n\n",
		updated.RetentionDays, updated.EncryptionReq)

	// Method 2: Update by Path and Framework
	fmt.Println("3. Update by path and framework...")
	fmt.Println("   Updating SOC2 tag for /customer-data")

	err = ctm.UpdateTagByPathAndFramework(ctx, "/customer-data", velocity.FrameworkSOC2,
		func(tag *velocity.ComplianceTag) error {
			tag.AuditLevel = "high"
			tag.AccessPolicy = "soc2-access-policy"
			return nil
		})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ SOC2 tag updated with high audit level and access policy")

	// Show individual tags
	allTags = ctm.GetTags("/customer-data")
	fmt.Println("Individual tags after updates:")
	for i, tag := range allTags {
		fmt.Printf("   Tag %d:\n", i+1)
		fmt.Printf("      ID: %s\n", tag.TagID)
		fmt.Printf("      Frameworks: %v\n", tag.Frameworks)
		fmt.Printf("      Retention: %d days\n", tag.RetentionDays)
		fmt.Printf("      Encryption: %v\n", tag.EncryptionReq)
		fmt.Printf("      Audit Level: %s\n", tag.AuditLevel)
		fmt.Printf("      Access Policy: %s\n", tag.AccessPolicy)
	}
	fmt.Println()

	// Method 3: Update all tags for a path
	fmt.Println("4. Update all tags for /customer-data...")

	err = ctm.UpdateAllTagsForPath(ctx, "/customer-data", func(tag *velocity.ComplianceTag) error {
		tag.Custodian = "data-protection-team"
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ All tags updated with custodian")

	// Verify
	allTags = ctm.GetTags("/customer-data")
	fmt.Println("After bulk update:")
	for _, tag := range allTags {
		fmt.Printf("   %v tag: Custodian=%s\n", tag.Frameworks, tag.Custodian)
	}
	fmt.Println()

	// Remove specific tag
	fmt.Println("5. Remove GDPR tag by ID...")
	fmt.Printf("   Removing tag ID: %s\n", gdprTag.TagID)

	err = ctm.RemoveTagByID(ctx, gdprTag.TagID)
	if err != nil {
		log.Fatal(err)
	}

	remaining := ctm.GetTags("/customer-data")
	fmt.Printf("   ✓ Removed! Remaining tags: %d\n", len(remaining))
	fmt.Printf("   Remaining: %v\n\n", remaining[0].Frameworks)

	fmt.Println("=== Summary ===")
	fmt.Println("✓ UpdateTag(tagID, fn) - Updates a specific tag by its unique ID")
	fmt.Println("✓ UpdateTagByPathAndFramework(path, framework, fn) - Updates first matching framework")
	fmt.Println("✓ UpdateAllTagsForPath(path, fn) - Updates all tags for a path")
	fmt.Println("✓ RemoveTagByID(tagID) - Removes a specific tag by ID")
	fmt.Println("\n This allows precise control over which tags to update!")
}

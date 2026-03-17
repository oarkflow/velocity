package velocity

import (
	"context"
	"testing"
)

func TestComplianceTagManager_MultipleTagsUpdate(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Apply multiple tags to the same path
	gdprTag := &ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []ComplianceFramework{FrameworkGDPR},
		DataClass:     DataClassConfidential,
		RetentionDays: 365,
		CreatedBy:     "privacy-officer",
	}
	err = ctm.TagPath(ctx, gdprTag)
	if err != nil {
		t.Fatalf("Failed to tag with GDPR: %v", err)
	}

	soc2Tag := &ComplianceTag{
		Path:          "/customer-data",
		Frameworks:    []ComplianceFramework{FrameworkSOC2},
		DataClass:     DataClassConfidential,
		RetentionDays: 730,
		CreatedBy:     "security-officer",
	}
	err = ctm.TagPath(ctx, soc2Tag)
	if err != nil {
		t.Fatalf("Failed to tag with SOC2: %v", err)
	}

	// Verify both tags exist
	allTags := ctm.GetTags("/customer-data")
	if len(allTags) != 2 {
		t.Fatalf("Expected 2 tags, got %d", len(allTags))
	}

	// Test 1: Update specific tag by TagID
	gdprTagID := allTags[0].TagID
	err = ctm.UpdateTag(ctx, gdprTagID, func(tag *ComplianceTag) error {
		tag.RetentionDays = 500 // Update only GDPR tag
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to update by TagID: %v", err)
	}

	// Verify only the GDPR tag was updated
	updatedTags := ctm.GetTags("/customer-data")
	var gdprUpdated, soc2Unchanged bool
	for _, tag := range updatedTags {
		if tag.TagID == gdprTagID && tag.RetentionDays == 500 {
			gdprUpdated = true
		}
		if tag.Frameworks[0] == FrameworkSOC2 && tag.RetentionDays == 730 {
			soc2Unchanged = true
		}
	}
	if !gdprUpdated {
		t.Error("GDPR tag was not updated")
	}
	if !soc2Unchanged {
		t.Error("SOC2 tag should not have changed")
	}

	// Test 2: Update by path and framework
	err = ctm.UpdateTagByPathAndFramework(ctx, "/customer-data", FrameworkSOC2, func(tag *ComplianceTag) error {
		tag.EncryptionReq = true
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to update by path and framework: %v", err)
	}

	// Verify SOC2 tag was updated
	soc2Updated := false
	updatedTags = ctm.GetTags("/customer-data")
	for _, tag := range updatedTags {
		if tag.Frameworks[0] == FrameworkSOC2 && tag.EncryptionReq {
			soc2Updated = true
		}
	}
	if !soc2Updated {
		t.Error("SOC2 tag was not updated")
	}

	// Test 3: Update all tags for a path
	err = ctm.UpdateAllTagsForPath(ctx, "/customer-data", func(tag *ComplianceTag) error {
		tag.AuditLevel = "high"
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to update all tags: %v", err)
	}

	// Verify all tags have high audit level
	allUpdatedTags := ctm.GetTags("/customer-data")
	for _, tag := range allUpdatedTags {
		if tag.AuditLevel != "high" {
			t.Errorf("Tag %s does not have high audit level", tag.TagID)
		}
	}

	// Test 4: Remove specific tag by ID
	err = ctm.RemoveTagByID(ctx, gdprTagID)
	if err != nil {
		t.Fatalf("Failed to remove tag by ID: %v", err)
	}

	// Verify only SOC2 tag remains
	remainingTags := ctm.GetTags("/customer-data")
	if len(remainingTags) != 1 {
		t.Fatalf("Expected 1 tag remaining, got %d", len(remainingTags))
	}
	if remainingTags[0].Frameworks[0] != FrameworkSOC2 {
		t.Error("Wrong tag removed - SOC2 tag should remain")
	}
}

func TestComplianceTagManager_TagIDGeneration(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Test 1: Auto-generated TagID
	tag1 := &ComplianceTag{
		Path:       "/data1",
		Frameworks: []ComplianceFramework{FrameworkGDPR},
		CreatedBy:  "user1",
	}
	err = ctm.TagPath(ctx, tag1)
	if err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	retrieved1 := ctm.GetTag("/data1")
	if retrieved1.TagID == "" {
		t.Error("TagID should be auto-generated")
	}

	// Test 2: Custom TagID
	tag2 := &ComplianceTag{
		TagID:      "custom-tag-id-123",
		Path:       "/data2",
		Frameworks: []ComplianceFramework{FrameworkHIPAA},
		CreatedBy:  "user2",
	}
	err = ctm.TagPath(ctx, tag2)
	if err != nil {
		t.Fatalf("Failed to create tag with custom ID: %v", err)
	}

	retrieved2 := ctm.GetTag("/data2")
	if retrieved2.TagID != "custom-tag-id-123" {
		t.Errorf("Expected custom TagID 'custom-tag-id-123', got %s", retrieved2.TagID)
	}

	// Test 3: Multiple tags have unique IDs
	tag3 := &ComplianceTag{
		Path:       "/data1",
		Frameworks: []ComplianceFramework{FrameworkSOC2},
		CreatedBy:  "user3",
	}
	err = ctm.TagPath(ctx, tag3)
	if err != nil {
		t.Fatalf("Failed to create second tag for same path: %v", err)
	}

	allTags := ctm.GetTags("/data1")
	if len(allTags) != 2 {
		t.Fatalf("Expected 2 tags for /data1, got %d", len(allTags))
	}

	if allTags[0].TagID == allTags[1].TagID {
		t.Error("Tags should have unique IDs")
	}
}

func TestComplianceTagManager_UpdateErrors(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctm := NewComplianceTagManager(db)
	ctx := context.Background()

	// Test updating non-existent tag by ID
	err = ctm.UpdateTag(ctx, "non-existent-id", func(tag *ComplianceTag) error {
		return nil
	})
	if err == nil {
		t.Error("Expected error when updating non-existent tag")
	}

	// Test updating non-existent path
	err = ctm.UpdateTagByPathAndFramework(ctx, "/non-existent", FrameworkGDPR, func(tag *ComplianceTag) error {
		return nil
	})
	if err == nil {
		t.Error("Expected error when updating non-existent path")
	}

	// Create a tag
	tag := &ComplianceTag{
		Path:       "/test-data",
		Frameworks: []ComplianceFramework{FrameworkGDPR},
		CreatedBy:  "admin",
	}
	ctm.TagPath(ctx, tag)

	// Test updating with non-existent framework
	err = ctm.UpdateTagByPathAndFramework(ctx, "/test-data", FrameworkHIPAA, func(tag *ComplianceTag) error {
		return nil
	})
	if err == nil {
		t.Error("Expected error when updating with non-matching framework")
	}

	// Test removing non-existent tag
	err = ctm.RemoveTagByID(ctx, "non-existent-id")
	if err == nil {
		t.Error("Expected error when removing non-existent tag")
	}
}
